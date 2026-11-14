ownerProtocol({
  create: function (options) { return navigator.credentials.create(options); },
  get: function (options) { return navigator.credentials.get(options); }
}, function () { return window.chrome && window.chrome.webview; });
