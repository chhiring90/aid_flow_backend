---
title: contributors-leaderboard v1.0.0
language_tabs:
  - shell: Shell
  - http: HTTP
  - javascript: JavaScript
  - ruby: Ruby
  - python: Python
  - php: PHP
  - java: Java
  - go: Go
toc_footers: []
includes: []
search: true
code_clipboard: true
highlight_theme: darkula
headingLevel: 2
generator: "@tarslib/widdershins v4.0.17"
---

# contributors-leaderboard

> v1.0.0

Base URLs: https://api.contributor.kuosc.org.np

# Default

## GET get

GET /api/v1/webhook/

### Params

| Name  | Location | Type   | Required | Description     |
| ----- | -------- | ------ | -------- | --------------- |
| type  | query    | string | no       | commit or issue |
| limit | query    | number | no       | pagination      |
| page  | query    | number | no       | pagination      |

> Response Examples

> OK

```json
{
  "success": true,
  "data": {
    "docs": [
      {
        "_id": "64da5eedeb32c6b6ab959402", // document id from database
        "username": "erwinschrodinger1", // username of contribuor
        "userId": 81609547, // github user id of contributor
        "type": "commit", // type of contribution "commit"| "issue"
        "repositoryId": 675801461, // contributed repository id
        "repositoryName": "kuosc2005/website", // contribured repository name
        "__v": 0
      }
    ],
    "totalDocs": 5,
    "limit": 10,
    "totalPages": 1,
    "page": 1,
    "pagingCounter": 1,
    "hasPrevPage": false,
    "hasNextPage": false,
    "prevPage": null,
    "nextPage": null
  },
  "message": "Success"
}
```

### Responses

| HTTP Status Code | Meaning                                                 | Description | Data schema |
| ---------------- | ------------------------------------------------------- | ----------- | ----------- |
| 200              | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | OK          | Inline      |

### Responses Data Schema

# Data Schema
