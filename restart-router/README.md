# What is this?

Simple script that pings the outside and if it fails (after a few tries with increasing delay) it uses playwright to restart the router.

Define a `src/.env` file with

```
ROUTER_WEB_URL=http://xxx.xxx.xxx.xxx
ROUTER_WEB_USERNAME=xxx
ROUTER_WEB_PASSWORD=xxx
```

# Development

```
docker compose run --rm -i -P playwright bash -il

vncviewer localhost:5900

# optionally comment# optionally comment last line of `src/tests/reboot-router.spec.ts`
# to avoid actually rebooting the router.

# inside the container:
npx playwright test --project=firefox reboot-router --headed
# or:
npx playwright test --project=firefox reboot-router --ui
npx playwright codegen --browser=firefox http://some_url.com
```
