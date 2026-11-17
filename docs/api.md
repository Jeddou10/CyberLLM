# Local HTTP API

Start `python CyberLLM/server.py`; the default base URL is
`http://127.0.0.1:8000`. This API is for local use and has no built-in user
authentication. Requests and results are JSON unless serving an interface asset.

## Endpoints

| Method | Path | Request / response |
| --- | --- | --- |
| GET | `/`, `/index.html` | HTML interface. |
| GET | `/assets/styles.css` | Stylesheet. |
| GET | `/assets/app.js` | Browser script. |
| GET | `/api/health` | Provider implementation/model, live-provider flag, installed tool availability. |
| GET | `/api/examples` | Bundled example snippets and benchmark files. |
| GET | `/api/benchmark` | Benchmark manifest and label counts. |
| POST | `/api/scan` | `code`, optional `filename`, `log`, `deployment`, `deep` (default false). |
| POST | `/api/remediate` | `code`, optional `filename`, `deep` (default true), `findings` (prior finding list). Requires a live model. |
| POST | `/api/attack` | `code`, optional `filename`, `scenario`, `deployment`, `deep` (default false). |
| POST | `/api/attack_sim` | `code`, optional `filename`, `script` object, `scenario`. |
| POST | `/api/benchmark` | Optional `deep`, `window`, `remediate`. Defaults: false, ground-truth match window, false. |

Submit JSON booleans for boolean fields, not the strings `"true"` or `"false"`.
The default filename is `input.py`; its suffix affects analyzer selection.

## Scan example

```json
{
  "code": "import subprocess\nsubprocess.call(user_input, shell=True)\n",
  "filename": "example.py",
  "deep": false
}
```

A successful scan returns `ok`, `deep`, `deep_requested`, `provider`, `filename`,
`code`, and `record`. The record contains findings, the decision, proposed action,
guard verdict, and other pipeline details. Finding records include `rule_id`,
`severity`, `title`, `location`, `line`, `detail`, `source_agent`, and `evidence`.

## Error behavior

Blank code returns HTTP 400 on code-based endpoints. Unknown routes return 404.
Exceptions handled by the endpoints return 500 with an `error` string. Some
operation-level errors, such as remediation without a live provider, return
HTTP 200 with `ok: false`; clients must check both status and payload.

Responses are not cached (`Cache-Control: no-store`). Static file access is
limited to the HTML entry point and the two named UI assets. Configuration and
credential files are not served. See [security limitations](../SECURITY.md).
