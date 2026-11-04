// Preload for startup.test.js: makes the server process believe it runs on
// Windows, so the interim platform guard can be tested on any OS.
Object.defineProperty(process, 'platform', { value: 'win32' });
