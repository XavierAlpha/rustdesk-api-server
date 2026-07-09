# Web Client JS Bridge

This folder hosts the JavaScript/TypeScript bridge that the Flutter web client
calls via `window.getByName` and `window.setByName`.

## Commands
```bash
npm install
npm run build
```

The build outputs `dist/web_bridge.js`, which is loaded by
`flutter/web/index.html`.

## Dev
```bash
npm run dev
```

Use this for quick iteration while keeping `flutter run -d chrome` in another
terminal.

## Runtime design (WIP)
The web runtime is built in TypeScript under `web/js/src`. The `WebRuntime`
class exposes `setByName` and `getByName` for Flutter, manages session state,
and will host the protocol/transport implementation. Core goals:
- Keep browser glue isolated in `core/`.
- Put protocol and session logic in `runtime/`.
- Use protobuf definitions from `src/proto`.
