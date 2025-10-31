// VulnerableComponent.jsx
// Demonstrates Sonar rule javascript:S6761:
// "children" and "dangerouslySetInnerHTML" should not be used together
//
// WARNING: This file intentionally contains a bad pattern for educational/demo use only.

import React from 'react';
import ReactDOM from 'react-dom/client';

// A component that incorrectly mixes children with dangerouslySetInnerHTML
export function BadInnerHTMLComponent() {
  const htmlString = `<strong>Injected HTML:</strong> <em>This came from a raw string</em>`;

  return (
    // Noncompliant: dangerouslySetInnerHTML and children used together
    <div dangerouslySetInnerHTML={{ __html: htmlString }}>
      {/* These children conflict with dangerouslySetInnerHTML */}
      <p>This paragraph is a child node that will be overwritten by innerHTML.</p>
    </div>
  );
}

// Another example: passing children from parent + using dangerouslySetInnerHTML in child
export function ParentUsingBadChild() {
  const injected = `<ul><li>one</li><li>two</li></ul>`;

  return (
    <section>
      <h3>Parent demo</h3>
      <BadInnerHTMLComponent />
      <div dangerouslySetInnerHTML={{ __html: injected }}>
        {/* Child text — will conflict */}
        Fallback child text that will not survive innerHTML replacement.
      </div>
    </section>
  );
}

// Small demo app to mount the component so Sonar can analyze the codebase
export default function App() {
  return (
    <main>
      <h1>Sonar S6761 Demo</h1>
      <p>
        This app intentionally demonstrates the anti-pattern: using <code>children</code> together
        with <code>dangerouslySetInnerHTML</code>.
      </p>

      <ParentUsingBadChild />
    </main>
  );
}

// If you want to run this file directly (e.g., in CRA), include the following mounting code:
if (typeof document !== 'undefined') {
  const rootEl = document.getElementById('root') || document.createElement('div');
  rootEl.id = 'root';
  if (!document.body.contains(rootEl)) document.body.appendChild(rootEl);

  const root = ReactDOM.createRoot(rootEl);
  root.render(<App />);
}
