-- Anthropic first-party prices, USD per million tokens, as published on
-- 2026-11-01. Patterns end in '*' so dated snapshot ids match; the
-- longest matching pattern wins, so claude-opus-5-5* beats claude-opus-5*.
--
-- Cache write prices are 1.25x (5m) and 2x (1h) base input. Cache reads
-- are 0.1x base input except where the pricing page says otherwise.
-- inference_geo "us" is 1.1x on every token price for 4.6 and later.
-- Web search is $10 per 1,000 searches on every model.

INSERT INTO price (model_pattern, speed, min_prompt_tokens, effective_from,
                   input_usd_per_mtok, output_usd_per_mtok,
                   cache_write_5m_usd_per_mtok, cache_write_1h_usd_per_mtok,
                   cache_read_usd_per_mtok, web_search_usd_per_1k,
                   geo_multipliers, note)
VALUES
    ('claude-fable-5-1*',  'standard', 0, '1970-01-01Z', 10,   50,   12.50, 20,   0.25, 10, '{"us": 1.1}', 'seed'),
    ('claude-mythos-5-1*', 'standard', 0, '1970-01-01Z', 10,   50,   12.50, 20,   0.25, 10, '{"us": 1.1}', 'seed'),
    ('claude-fable-5*',    'standard', 0, '1970-01-01Z', 10,   50,   12.50, 20,   1,    10, '{"us": 1.1}', 'seed'),
    ('claude-mythos-5*',   'standard', 0, '1970-01-01Z', 10,   50,   12.50, 20,   1,    10, '{"us": 1.1}', 'seed'),
    ('claude-opus-5-5*',   'standard', 0, '1970-01-01Z', 4,    20,   5,     8,    0.20, 10, '{"us": 1.1}', 'seed'),
    ('claude-opus-5-5*',   'fast',     0, '1970-01-01Z', 8,    40,   10,    16,   0.40, 10, '{"us": 1.1}', 'seed: fast mode'),
    ('claude-opus-5*',     'standard', 0, '1970-01-01Z', 5,    25,   6.25,  10,   0.50, 10, '{"us": 1.1}', 'seed'),
    ('claude-opus-5*',     'fast',     0, '1970-01-01Z', 10,   50,   12.50, 20,   1,    10, '{"us": 1.1}', 'seed: fast mode'),
    ('claude-opus-4-8*',   'standard', 0, '1970-01-01Z', 5,    25,   6.25,  10,   0.50, 10, '{"us": 1.1}', 'seed'),
    ('claude-opus-4-8*',   'fast',     0, '1970-01-01Z', 10,   50,   12.50, 20,   1,    10, '{"us": 1.1}', 'seed: fast mode'),
    ('claude-opus-4-7*',   'standard', 0, '1970-01-01Z', 5,    25,   6.25,  10,   0.50, 10, '{"us": 1.1}', 'seed'),
    ('claude-opus-4-6*',   'standard', 0, '1970-01-01Z', 5,    25,   6.25,  10,   0.50, 10, '{"us": 1.1}', 'seed'),
    ('claude-sonnet-5-5*', 'standard', 0, '1970-01-01Z', 2,    10,   2.50,  4,    0.10, 10, '{"us": 1.1}', 'seed'),
    ('claude-sonnet-5*',   'standard', 0, '1970-01-01Z', 2,    10,   2.50,  4,    0.20, 10, '{"us": 1.1}', 'seed'),
    ('claude-sonnet-4-6*', 'standard', 0, '1970-01-01Z', 3,    15,   3.75,  6,    0.30, 10, '{"us": 1.1}', 'seed'),
    ('claude-haiku-5-5*',  'standard', 0,      '1970-01-01Z', 0.10, 0.50, 0.125, 0.20, 0.01, 10, '{"us": 1.1}', 'seed: prompts up to 100k'),
    ('claude-haiku-5-5*',  'standard', 100001, '1970-01-01Z', 0.50, 2.50, 0.625, 1,    0.05, 10, '{"us": 1.1}', 'seed: prompts over 100k'),
    ('claude-haiku-4-5*',  'standard', 0, '1970-01-01Z', 1,    5,    1.25,  2,    0.10, 10, '{}', 'seed');
