## 1. Does user input reach rendered server output?

Examples:
- page content
- preview
- email body
- report
- rendered message
- template-driven document/output

- **Yes** -> continue
- **No** -> SSTI less likely

## 2. Does the app/stack suggest server-side templating?

Examples:
- Jinja2
- Twig
- Blade
- Smarty
- Freemarker
- Velocity
- server-rendered pages/messages

- **Yes** -> continue
- **No** -> continue only if behaviour still suggests SSTI

## 3. Test simple expression payloads

Test input as plain data first, then with template-style syntax.

Examples:

`{{7*7}}`
`${7*7}`
`<%= 7*7 %>`
`#{7*7}`

## 4. Did the response change in a way that suggests template evaluation?

Positive signs:
- `49` returned instead of literal payload
- payload partly processed
- input disappears after render
- template/render/parser error appears
- output changes before it reaches the browser

- **Yes** -> SSTI likely -> continue
- **No** -> SSTI not identified yet

## 5. Confirm with one more benign payload from the same syntax family

Examples:

`{{7+7}}`
`${7+7}`
`<%= 7+7 %>`
`#{7*7}`

- **If evaluated** -> SSTI identified
- **If not** -> reassess syntax/engine/context

## 6. Next move

- If SSTI identified -> [[Exploiting SSTI by Engine]]
- If not identified -> continue main test flow / gather stack clues


