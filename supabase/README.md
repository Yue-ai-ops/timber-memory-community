# Timber Collab 后端迁移与安全验证

本目录包含可审阅的 PostgreSQL 迁移和验证说明。本次没有连接 Supabase、创建项目、上传文件或发送真实邮件。迁移面向 Supabase Free：微信网页前端用 Supabase Auth 匿名登录取得设备 UID，再通过群内邀请口令加入；前端可用原生 `fetch` 调 Auth/PostgREST/Storage，不需要安装 Supabase JS SDK。浏览器只允许持有项目 URL 与 anon/publishable key；`service_role`、数据库口令和任何私钥都不能进入前端、公开仓库或 Pages 构建变量。

## 数据边界

- `members` 没有客户端直接写权限；用户只可读自己的成员行。Auth 匿名登录只创建 Supabase Auth 用户，不赋予业务成员权限。用户必须经 `redeem_invite` 成功后才建立 active `member` 行；普通成员不能创建/修改自己的成员行或升为管理员。首次管理员由可信操作者通过 SQL 将已核实的匿名 Auth UID 加入为 active `admin`。
- `invite_codes` 只允许活跃管理员读取元数据，成员不能读写。建邀请码/撤销必须走管理员 RPC。数据库只存 256-bit 随机口令的 SHA-256，`create_invite` 仅返回一次明文；前端应只在管理员操作成功后向管理员显示，并避免 console、analytics、公开 fixtures、URL 或仓库留存。兑换按邀请码行加锁、检查有效期/撤销/使用上限并在成功时计数；每个 UID 每 15 分钟最多尝试 5 次，失败以 JSON 返回以便速率计数提交。
- `submissions` 只能由已激活成员创建自己的 `pending` 记录。客户端不能设置 `owner_id`、`status`、`revision`、审核备注和时间戳；没有直接 UPDATE 权限。编辑经 `update_submission` RPC 锁行并核验 revision。
- 活跃成员可读全部 `team` 提交；`private` 仅提交者与活跃管理员可读。匿名角色对业务表没有权限。审核历史和地图版本不可由客户端直接写，且拒绝 UPDATE/DELETE。
- 审核只可由活跃管理员经 `review_submission` 执行；批准、退回补充、拒绝都会锁定版本并追加审阅记录。批准不会自动改写地图。
- `assets` 只能经 `register_asset` 登记：它锁定提交行（与审核/编辑串行），核验提交仍可编辑且属于当前用户，并确认同 bucket 中已经存在完全匹配的对象路径。相同路径与相同登记内容的重试幂等；同一提交内 sha256 唯一，冲突拒绝。私有 bucket 通过 Storage RLS 限定对象路径为 `auth.uid()/submission_id/file`；读取还要通过提交可见性判断。仅有对象 URL 不绕过私有 bucket 授权。对象最大 50 MiB，并限制到迁移中的 MIME allowlist；RPC 检查文件登记字段约束，但不依赖未确认的 Storage `metadata` JSON key 来比对对象字节数/MIME。
- 管理员正式提交地图快照经 `create_map_version`；所有激活成员可读版本内容（其中可能包含内部住户备注）。不要把未经授权的住户信息放进地图版本。

`is_active_member()`、`is_active_admin()`、`can_read_submission(uuid)`、`can_upload_submission_asset(uuid)` 和 `can_delete_submission_asset(uuid)` 是返回单个布尔值的授权帮助函数，不返回成员列表或成员资料。它们使用 `SECURITY DEFINER` 和固定 `search_path`，并撤销默认 `PUBLIC` 执行权。RPC 同样固定 search path、检查 Supabase 已验证 JWT 对应的 `auth.uid()`/权限和行所有权，且撤销 anon/PUBLIC 调用权。此处的 API `anon` role 与“匿名登录后拿到的用户 JWT”不同：匿名用户 JWT 通常以 `authenticated` role 调用，但未加入 active members 前仍读不到协作资料，也不能写业务内容。

## 关键 RPC 接口

PostgREST 中通过 `/rest/v1/rpc/<function_name>` 调用，使用 Supabase Auth access token 和 anon/publishable key。请求参数名须与下列名称一致。

```text
update_submission(
  p_id uuid,
  p_expected_revision integer,
  p_author text,
  p_title text,
  p_story text,
  p_captured_year text,
  p_building_id text,
  p_x real,
  p_y real,
  p_kind public.submission_kind,
  p_privacy public.submission_privacy
) returns public.submissions

review_submission(
  p_id uuid,
  p_expected_revision integer,
  p_status public.submission_status, -- needs_info | approved | rejected
  p_review_note text
) returns public.submissions

register_asset(
  p_submission_id uuid,
  p_object_path text, -- <auth.uid()>/<submission_id>/<filename>
  p_filename text,
  p_mime text,
  p_bytes bigint,
  p_sha256 text
) returns public.assets

create_map_version(
  p_payload jsonb,
  p_note text,
  p_previous_id uuid default null
) returns public.map_versions

create_invite(
  p_label text,
  p_days integer default 7,       -- 1..90 days
  p_max_uses integer default 20   -- 1..1000 uses
) returns text                   -- one-time plaintext token

redeem_invite(
  p_code text,
  p_display_name text
) returns jsonb                   -- {success, reason?, already_member?, display_name?}

revoke_invite(p_invite_id uuid) returns boolean
```

每次客户端编辑都应携带最后读到的 `revision`；RPC 成功后用返回行里的 revision 替换本地值。收到 SQLSTATE `40001` 时重新取记录并让用户处理冲突，不能自动重发旧内容。审核 RPC 也要求 expected revision；不允许审核已 approved/rejected 的记录。上传流程先确认提交由当前用户拥有且处于 pending/needs_info，再向私有 bucket 上传对象，随后调用 `register_asset`。对象路径的 filename 应为单个路径段；推荐使用 UUID 文件名并把原名存在 `filename` 元数据字段。正式新增地图版本时，`p_previous_id` 必须等于当前唯一 head（首版为 null）；系统用事务 advisory lock 串行化建版，并拒绝过期 head，避免并发管理员产生分叉。

兑换失败返回 `success:false` 和通用原因码，不抛 SQL 异常，避免速率限制写入随事务回滚。邀请码不可猜测，应由群管理员通过私下可信渠道发布；不要写入公开代码仓库或公开 demo data。一个已经 active 的成员再次兑换会返回 `already_member:true`，不会增加邀请码使用次数。

## 首次配置与管理员引导

1. 在 Supabase 新项目 SQL Editor 中人工检查并执行 `schema.sql`。该脚本是单次初始迁移，含 `begin/commit`、扩展/类型/表/策略创建，不是可反复执行的幂等迁移；不要对已有生产项目盲目重跑。此步骤仅为说明，当前任务没有执行它。
2. 在 Supabase Auth 设置中启用 anonymous sign-in。可信管理员在微信网页创建匿名会话，然后由操作者在 Dashboard 的 Auth 用户列表核对该用户 UID 与现实管理员身份。此流程不需要邮箱、密码或发送真实邮件。匿名 UID 是身份标识，不是凭据。
3. 操作者确认 UID 后，在 Dashboard SQL Editor 执行下列占位模板；把两处占位符替换为已核实值，不能原样执行：

```sql
insert into public.members (user_id, display_name, role, active)
select id, '<确认过的显示名>', 'admin', true
from auth.users
where id = '<已核实的 Auth UUID>'::uuid
on conflict (user_id) do update
set display_name = excluded.display_name,
    role = 'admin',
    active = true;
```

不要通过客户端写入 members，也不要为了首次管理员而禁用 JWT 校验。之后由管理员在受限页面调用 `create_invite`，把一次性口令私下发到获准的微信群；用户在微信网页匿名登录后调用 `redeem_invite`。SQL 操作者仍可在身份核验后手工停用成员或撤销管理员。

## 后端安全测试说明

执行迁移后，在隔离测试项目准备 API `anon`、匿名登录但未兑换邀请码的 UID、已激活普通成员 A/B，以及管理员；建 A/B 自己的 pending 与 needs_info 提交，并建 team/private、approved/rejected 样本。所有写请求用各自登录取得的短期 access token；不要把 token 写入日志或提交到仓库。测试可以从浏览器 Network/local REST client 对 Auth、REST、RPC、Storage API 发请求。

| 验证 | 预期结果 |
| --- | --- |
| anon 读 members/submissions/assets/map_versions/reviews | 拒绝或空结果；不得返回业务行 |
| 未激活账号查询、插入或调用编辑/上传/map RPC | 无业务数据；写调用拒绝 |
| 普通成员读邀请码表、创建或撤销邀请码 | 拒绝；成员只可经 redeem_invite 兑换 |
| admin 创建邀请码 | 返回一次性口令；数据库只存 SHA-256，不可从表中还原明文 |
| UID 兑换有效邀请码 | 成功加入 active member，role固定member，使用次数加1 |
| active成员再次兑换、普通成员以自己UID尝试升admin | 前者 already_member 且不消耗次数；后者始终不能改 role |
| 无效/过期/撤销/用尽邀请码 | 返回通用失败JSON，成员行不变，使用次数不增加 |
| 同一邀请码并发兑换超过use_limit | 只允许达到上限的调用成功，其他失败 |
| 同一 UID 15分钟内重复失败调用6次 | 前5次验证；第6次起 rate_limited，失败计数在事务结束后保留 |
| A 查询 team 提交 | 可见所有 team 状态（按产品需要过滤展示），不可见 B 的 private |
| A 查询自己的 private、管理员查询任一 private | 可见；B 不可见 A 的 private |
| A 插入 owner_id=B、status=approved/needs_info、revision>1 的 submission | 数据库列权限或 RLS 拒绝；合法插入默认为 A/pending/revision=1 |
| A 直接 PATCH submissions，或直接改 role/status/review_note | 拒绝（客户端无 UPDATE 权限） |
| A 编辑自己的 pending/needs_info 且 revision 匹配 | 成功，revision 加 1，updated_at 更新 |
| A 编辑他人记录、已 approved/rejected 的记录或错误 revision | 拒绝；错误 revision 为 SQLSTATE 40001，原行不变 |
| 普通成员调用 review_submission/create_map_version | 拒绝；不新增审阅记录/地图版本 |
| admin 审核 pending/needs_info，revision 匹配 | 成功，revision 加 1，审阅历史追加一行 |
| admin 用旧 revision 再审、重复审 approved/rejected | 拒绝；历史不得多出一行 |
| 任意客户端 UPDATE/DELETE submission_reviews 或 UPDATE/DELETE map_versions | 拒绝；两表 append-only |
| A 上传到 B 的 UID 文件夹、B 的 submission、其他 bucket 或错误路径层级 | Storage 拒绝 |
| A 上传到自己的 pending/needs_info，文件超 50 MiB 或不允许 MIME | 合法小文件允许；越权、超限或 MIME 不符拒绝 |
| 通过猜测的 public URL 读取对象、A 读取 B private 文件 | 拒绝；A 读取 team 文件及 owner/admin 读取 private 文件成功 |
| A 删除自己 pending 对象、删除他人对象或删除 needs_info/approved 对象 | 仅 pending 自有对象允许；其余拒绝 |
| A 为他人/不可编辑提交登记资产元数据、重复 object_path | 拒绝 |
| A 为尚未上传的路径调用 register_asset | 拒绝；Storage 中必须已存在同 bucket、同路径对象 |
| A 用完全相同参数重试 register_asset | 返回既有行，不重复创建；同提交相同 sha256 但不同内容/路径拒绝 |
| 非 admin 调 create_map_version；成员读取 admin 已建版本 | 写拒绝；激活成员可读 |
| 两个 admin 用同一个过期 previous_id 并发调用 create_map_version | 一个成功；后续请求因 head conflict 拒绝，不能产生分叉 |
| 传入 x/y 单边 null、超边界坐标、超长标题/故事、非法 hash/MIME | 数据库约束拒绝 |

同时检查 PostgREST 的 OPTIONS/错误响应没有泄露 service-role key；确认 `storage.buckets.public=false`，bucket 大小/MIME 配置与 SQL 一致。安全拒绝应查看真实 HTTP 状态及响应，不以“前端按钮隐藏”作为验证。测试结束后删除隔离测试数据，并轮换任何曾被误写入日志的临时凭据。

### 本次验证范围

迁移主体已在本地 PGlite 隔离进程中使用模拟的 `auth.users`/`auth.uid()` 和 `storage.buckets`/`storage.objects` 结构执行。测试 harness 跳过了 PGlite 不支持的 `CREATE EXTENSION pgcrypto`，并用确定性 `gen_random_bytes`/`digest` 接口替身；因此本次不代表验证了扩展安装语句、真实随机数质量或 SHA-256 实现。安全用例覆盖 anon 表/RPC 拒绝、未激活用户不能写、成员不能伪造 owner_id/升权/读取他人 private、管理员审核及审阅记录、NULL/stale revision 冲突、资产对象存在校验与幂等登记、畸形 storage UUID 不可见、地图 head 冲突、邀请码权限/兑换/固定 member role/使用上限/UID 限流/active重试/撤销。PGlite 不是 Supabase 托管 PostgreSQL/Storage/Auth 的完整替代；未连接 Supabase，因此真实 pgcrypto 安装路径、bucket 服务器限制、JWT 签发、并发部署/网络行为仍需在隔离 Supabase 项目复验。

## 公开仓库与素材边界

公开代码只能包含 schema、无真实数据的说明和通用前端代码。不得提交真实照片/视频/模型、住户姓名/备注、准确楼栋坐标、导出地图、auth.users 内容、JWT、anon/service-role key、DB URL、密码或 `.env`。anon key 虽可由浏览器使用，也只能以公开配置方式提供且必须依赖上述 RLS；service-role 永不放进浏览器或公开仓库。真实素材保存在私有 bucket，不以可猜 URL 或公开 Pages 静态资源方式发布。
