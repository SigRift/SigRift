/**
 * Decode one layer of Python html.escape's text representation.
 * Only use for API fields documented as HTML-encoded (condition-rule names,
 * alert messages and acknowledgement notes, and the activity log's event
 * type, node and message). Alert names have mixed origins.
 * The result is plain text, NOT safe HTML: use textContent, input.value or esc().
 * A single pass preserves intentional literal entities and does not guess at
 * legacy data that may have been encoded repeatedly by an older edit form.
 */
"use strict";

window.decodeHtmlEscapedText = function(value) {
    if (value == null) return "";
    var entities = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#x27;": "'" };
    return String(value).replace(/&(?:amp|lt|gt|quot|#x27);/g, function(entity) {
        return entities[entity];
    });
};
