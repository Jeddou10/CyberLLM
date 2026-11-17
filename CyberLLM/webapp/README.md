# Local web interface

The interface has no frontend build step or package dependencies:

- `index.html` contains the markup.
- `assets/styles.css` contains the styles.
- `assets/app.js` is a classic script loaded at the end of the document.

Run `python CyberLLM/server.py` from the repository root and open
http://127.0.0.1:8000. The app uses root-relative asset and API URLs; serve it
through the Python server rather than opening the HTML file directly.

The server exposes only the two named asset paths. API details are in
[docs/api.md](../../docs/api.md). No bundler, module conversion, or UI behavior
change is required to edit these files.
