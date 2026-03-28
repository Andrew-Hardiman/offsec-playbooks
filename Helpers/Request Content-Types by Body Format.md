
| Body format                  | `Content-Type`                      | Example body                                         |
| ---------------------------- | ----------------------------------- | ---------------------------------------------------- |
| Standard HTML form data      | `application/x-www-form-urlencoded` | `username=andrew&password=hello123`                  |
| File upload / multipart form | `multipart/form-data`               | boundary-separated parts containing fields and files |
| JSON                         | `application/json`                  | `{"username":"andrew","admin":false}`                |
| XML                          | `application/xml`                   | `<user><name>andrew</name></user>`                   |
| Plain text                   | `text/plain`                        | `hello this is just raw text`                        |
| HTML                         | `text/html`                         | `<h1>Hello</h1><p>Test</p>`                          |
| Raw binary bytes             | `application/octet-stream`          | non-human-readable raw bytes                         |