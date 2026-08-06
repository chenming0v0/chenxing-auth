-- 「不存在生效默认套餐」是合法状态（平台未开放自助接入），因此这里不再
-- 修复数据、也不再断言必须存在 active 默认套餐。唯一保留的不变式是：
-- 归档套餐不能同时是默认套餐，否则默认套餐指向一个已下线的套餐。
ALTER TABLE plans
    ADD CONSTRAINT plans_default_must_be_active CHECK (status = 'active' OR is_default = FALSE);
