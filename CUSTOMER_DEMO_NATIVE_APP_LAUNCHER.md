# WSO2 IS 7.3 — Native Application Launcher Demo

## Demo URL

`https://localhost:9443/myaccount/applications`

This is the shipped WSO2 My Account portal — not a custom launcher.

## Start

```bash
./demo.sh reset
./demo.sh launcher
```

## Personas

- `alice / Alice@123`: Portal Corporativo + Finance Workspace
- `carol / Carol@123`: Portal Corporativo + Security Operations
- `bob`: no tiles from these entitlement groups

## Presenter flow

1. Open a fresh incognito window.
2. Open the native launcher URL.
3. WSO2 asks the user to authenticate and returns to Applications.
4. Sign in as Alice and show her group-filtered catalog.
5. Click Finance Workspace. It launches a registered OIDC application.
6. The existing WSO2 browser session is reused, so no second password prompt should appear.
7. Repeat with Carol and show a different native catalog.

The MarketSphere React runtime is reused behind the sample application tiles only to keep the POC compact. The application catalog itself and its group filtering are native WSO2 Identity Server features.
