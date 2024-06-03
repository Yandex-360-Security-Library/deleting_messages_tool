# Yandex 360 Deleting Messages Tool
Performs searching and deleting emails by rfc-id in the organization

##Usage
```
Script for searching emails with a subject for the last N days in yandex 360 organizations.

Environment options:
OAUTH_TOKEN - OAuth Token,
ORGANIZATION_ID - Organization ID,
APPLICATION_CLIENT_ID - WEB Application ClientID,
APPLICATION_CLIENT_SECRET - WEB Application secret

For example:
OAUTH_TOKEN="AgAAgfAAAAD4beAkEsWrefhNeyN1TVYjGT1k",
ORGANIZATION_ID=123,
APPLICATION_CLIENT_ID = "123BbCc4Dd5Ee6FffFassadsads",
APPLICATION_CLIENT_SECRET = "00b31Fasse8a481eaaf75955c175a20f",

options:
  -h, --help                          show this help message and exit
  --rfc-message-id RFC_MESSAGE_ID     Message subject
  --date-ago DATE_AGO                 Number of days to review [0, 90]
```
