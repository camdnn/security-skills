# Evaluation report

## Summary

| Metric | Mean | Minimum | Std-dev |
| --- | ---: | ---: | ---: |
| Precision | 1.000 | 1.000 | 0.000 |
| Recall | 1.000 | 1.000 | 0.000 |
| F1 | 1.000 | 1.000 | 0.000 |

Stable recall: 1.000. Fixture passes: 28/28.

## Agent

claude

## Baseline comparison

Baseline: claude / fast.

Mean F1: 1.000 (▲ +0.034 vs baseline).
- no regression detected

## Top false negatives

None.

## Top false positives

None.

## Warnings

None.

## Failed trials

- secrets-check-code-only-2: agent exited 1: imit":0,"concurrency_limit":0,"budget":0},"by_type":{}},"safety_stops":0,"is_error":true,"num_turns":9,"subtype":"success","api_error_status":429,"api_error_type":"rate_limit_error","api_error_origin":"first_party","api_error":"usage_limit_reached","result":"you've hit your 5-hour limit · resets 7:40pm (america/los_angeles)","type":"result","duration_ms":6304,"uuid":"9681a475-112b-4a08-9e42-582a2cb0153c","queued_turn_count":0,"result_index":0,"credential_expires_at":"2026-12-17t08:43:05.408z"}


- secrets-check-code-only-3: agent exited 1: limit":0,"concurrency_limit":0,"budget":0},"by_type":{}},"safety_stops":0,"is_error":true,"num_turns":1,"subtype":"success","api_error_status":429,"api_error_type":"rate_limit_error","api_error_origin":"first_party","api_error":"usage_limit_reached","result":"you've hit your 5-hour limit · resets 7:40pm (america/los_angeles)","type":"result","duration_ms":885,"uuid":"f00bc80a-5a4b-4e18-a787-a19cde256ca8","queued_turn_count":0,"result_index":0,"credential_expires_at":"2026-12-17t08:43:05.408z"}


- xss-check-code-only-1: agent exited 1: limit":0,"concurrency_limit":0,"budget":0},"by_type":{}},"safety_stops":0,"is_error":true,"num_turns":1,"subtype":"success","api_error_status":429,"api_error_type":"rate_limit_error","api_error_origin":"first_party","api_error":"usage_limit_reached","result":"you've hit your 5-hour limit · resets 7:40pm (america/los_angeles)","type":"result","duration_ms":725,"uuid":"5d21ccd7-77d2-442c-ad38-fd4512419f9f","queued_turn_count":0,"result_index":0,"credential_expires_at":"2026-12-17t08:43:05.408z"}


- xss-check-code-only-2: agent exited 1: limit":0,"concurrency_limit":0,"budget":0},"by_type":{}},"safety_stops":0,"is_error":true,"num_turns":1,"subtype":"success","api_error_status":429,"api_error_type":"rate_limit_error","api_error_origin":"first_party","api_error":"usage_limit_reached","result":"you've hit your 5-hour limit · resets 7:40pm (america/los_angeles)","type":"result","duration_ms":782,"uuid":"2abeba35-a178-4e22-a8c9-9146e6e14151","queued_turn_count":0,"result_index":0,"credential_expires_at":"2026-12-17t08:43:05.408z"}


- xss-check-code-only-3: agent exited 1: limit":0,"concurrency_limit":0,"budget":0},"by_type":{}},"safety_stops":0,"is_error":true,"num_turns":1,"subtype":"success","api_error_status":429,"api_error_type":"rate_limit_error","api_error_origin":"first_party","api_error":"usage_limit_reached","result":"you've hit your 5-hour limit · resets 7:40pm (america/los_angeles)","type":"result","duration_ms":788,"uuid":"cf687133-3297-49cd-90f5-7a5c7ef86739","queued_turn_count":0,"result_index":0,"credential_expires_at":"2026-12-17t08:43:05.408z"}



## Skipped trials

None.

## Tokens

Not reported.
