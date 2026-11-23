/* Documentation menu ("?") in the dashboard and admin headers.
 *
 * The button opens and closes the menu that follows it; a click anywhere
 * outside an open menu closes it. The pages run under the gateway's
 * `script-src 'self'`, which refuses inline script and onclick
 * attributes, so the behaviour is bound here.
 */
(function() {
    "use strict";
    var OPEN = "docs-dropdown-open";

    function bind() {
        var buttons = document.querySelectorAll(".docs-dropdown .help-icon");
        Array.prototype.forEach.call(buttons, function(button) {
            button.addEventListener("click", function() {
                var menu = button.nextElementSibling;
                if (menu && menu.classList.contains("docs-dropdown-menu")) {
                    menu.classList.toggle(OPEN);
                }
            });
        });
        document.addEventListener("click", function(e) {
            var menus = document.querySelectorAll(".docs-dropdown-menu");
            Array.prototype.forEach.call(menus, function(menu) {
                if (!menu.parentElement || !menu.parentElement.contains(e.target)) {
                    menu.classList.remove(OPEN);
                }
            });
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bind);
    } else {
        bind();
    }
})();
