# UI test

Renders the dashboard in a real DOM and asserts against a live scan payload.
Catches what `node --check` cannot: cascade bugs, missing elements, handlers
that throw, and accessibility invariants.

It loads `style.css` inline, because jsdom does not fetch `<link>` — without
that the cascade is never exercised, and an author `display` rule silently
defeating the `hidden` attribute goes unseen. That is exactly how the tab
panels shipped broken once.

```sh
cd test
npm install jsdom          # not vendored; this is a dev-only dependency
curl -s http://127.0.0.1:7777/api/state > state.json
node ui_test.mjs state.json
```

Exits non-zero if any assertion fails.
