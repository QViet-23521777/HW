// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';

// CRA (react-scripts@5) + some Node/JSDOM combos don't expose TextEncoder/TextDecoder globally.
// Our WebCrypto-based modules rely on them for UTF-8 encoding.
// eslint-disable-next-line no-undef
if (typeof TextEncoder === 'undefined' || typeof TextDecoder === 'undefined') {
  // eslint-disable-next-line global-require
  const { TextDecoder: NodeTextDecoder, TextEncoder: NodeTextEncoder } = require('util');
  // eslint-disable-next-line no-undef
  if (typeof TextEncoder === 'undefined') global.TextEncoder = NodeTextEncoder;
  // eslint-disable-next-line no-undef
  if (typeof TextDecoder === 'undefined') global.TextDecoder = NodeTextDecoder;
}
