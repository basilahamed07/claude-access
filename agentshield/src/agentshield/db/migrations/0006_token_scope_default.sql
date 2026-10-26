-- Fail closed: a token row written without a scope gets the restricted one. No product path ever issued an unrestricted
-- token before scopes existed, so every row already there is narrowed too.
update user_tokens set scope = 'ingest' where scope = 'full';
alter table user_tokens alter column scope set default 'ingest';
