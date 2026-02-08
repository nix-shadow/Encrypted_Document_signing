#!/usr/bin/env python3
"""
Generate a standalone HTML file of API documentation from OpenAPI spec
"""
import requests
import json

# Get OpenAPI spec
response = requests.get('http://localhost:3001/openapi.json')
spec = response.json()

# Create standalone HTML with embedded SwaggerUI
html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - API Documentation</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css">
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
        .swagger-ui .topbar {{
            display: none;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const spec = {spec_json};
            
            SwaggerUIBundle({{
                spec: spec,
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            }});
        }};
    </script>
</body>
</html>
"""

html_content = html_template.format(
    title=spec['info']['title'],
    spec_json=json.dumps(spec, indent=2)
)

# Save to file
output_file = 'api_documentation.html'
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(html_content)

print(f"✅ API documentation generated: {output_file}")
print(f"🌐 Open it in browser: file://{output_file}")
print(f"📸 Now you can take a screenshot!")
