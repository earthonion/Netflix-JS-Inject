# Netflix 'N Hack Payloads

After launching the hack, a JS server is populated waiting for payloads.

On this folder you have 2 examples:

- hello_world.js : Render a text on the UI using Netflix Gibbon internals

- Lapse (port from Y2JB): Currently activates Debug Settings. This is a 3 parts payload due to internal restrictions.
   - Execute in order:
      - 1_lapse_prepare_1.js
      - 2_lapse_prepare_2.js
      - 3_lapse_nf.js