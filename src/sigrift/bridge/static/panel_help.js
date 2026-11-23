/* Accessible, text-only panel explanations. No inline handlers or API calls. */
(function () {
    'use strict';

    class PanelHelp {
        constructor(document, window) {
            this.document = document;
            this.window = window;
            this.active = null;
            this.pinned = false;
            this.overTip = false;
            this.timer = null;
            this.tip = document.createElement('div');
            this.tip.id = 'panel-help-tooltip';
            this.tip.className = 'panel-help-tooltip';
            this.tip.setAttribute('role', 'tooltip');
            this.tip.hidden = true;
            document.body.appendChild(this.tip);
            document.querySelectorAll('[data-help][data-help-label]').forEach(heading => this.add(heading));
            this.tip.addEventListener('pointerenter', () => { this.overTip = true; this.cancelClose(); });
            this.tip.addEventListener('pointerleave', () => { this.overTip = false; this.scheduleClose(); });
            document.addEventListener('pointerdown', event => {
                if (this.active && !this.active.contains(event.target) && !this.tip.contains(event.target)) this.close();
            });
            document.addEventListener('focusin', event => {
                if (this.active && event.target !== this.active) this.close();
            });
            document.addEventListener('keydown', event => {
                if (event.key === 'Escape' && this.active) {
                    event.preventDefault();
                    event.stopPropagation();
                    this.close();
                }
            }, true);
            window.addEventListener('resize', () => this.position());
            window.addEventListener('scroll', () => this.position(), true);
        }

        add(heading) {
            const text = heading.getAttribute('data-help');
            const label = heading.getAttribute('data-help-label');
            if (!text || !label || heading.querySelector('.panel-help-button')) return;
            const button = this.document.createElement('button');
            button.type = 'button';
            button.className = 'panel-help-button';
            // The visual glyph is CSS-only: existing panel lookup uses heading textContent.
            button.setAttribute('aria-label', 'About ' + label);
            button.setAttribute('aria-expanded', 'false');
            button.addEventListener('focus', () => this.open(button, text));
            button.addEventListener('blur', () => { if (this.active === button) this.close(); });
            button.addEventListener('pointerenter', () => {
                this.cancelClose();
                if (this.active !== button) this.open(button, text);
            });
            button.addEventListener('pointerleave', () => this.scheduleClose());
            button.addEventListener('click', event => {
                // Information buttons inside a clickable card header must not collapse it.
                event.preventDefault();
                event.stopPropagation();
                if (this.active === button && this.pinned) this.close();
                else { this.open(button, text); this.pinned = true; }
            });
            button.addEventListener('keydown', event => {
                // Native Enter/Space activation still generates the button's click.
                if (event.key === 'Enter' || event.key === ' ') event.stopPropagation();
            });
            heading.appendChild(button);
        }

        cancelClose() {
            if (this.timer !== null) this.window.clearTimeout(this.timer);
            this.timer = null;
        }

        scheduleClose() {
            this.cancelClose();
            this.timer = this.window.setTimeout(() => {
                this.timer = null;
                if (!this.pinned && !this.overTip && this.document.activeElement !== this.active) this.close();
            }, 180);
        }

        open(button, text) {
            this.close();
            this.active = button;
            this.tip.textContent = text;
            this.tip.hidden = false;
            button.setAttribute('aria-describedby', this.tip.id);
            button.setAttribute('aria-expanded', 'true');
            this.position();
        }

        close() {
            this.cancelClose();
            if (this.active) {
                this.active.removeAttribute('aria-describedby');
                this.active.setAttribute('aria-expanded', 'false');
            }
            this.active = null;
            this.pinned = false;
            this.overTip = false;
            this.tip.hidden = true;
        }

        position() {
            if (!this.active) return;
            const anchor = this.active.getBoundingClientRect();
            if (!anchor.width || !anchor.height) { this.close(); return; }
            const box = this.tip.getBoundingClientRect();
            const gap = 8;
            const left = Math.max(gap, Math.min(anchor.left, this.window.innerWidth - box.width - gap));
            const below = anchor.bottom + gap;
            const top = below + box.height <= this.window.innerHeight - gap ? below : Math.max(gap, anchor.top - box.height - gap);
            this.tip.style.left = left + 'px';
            this.tip.style.top = top + 'px';
        }
    }

    window.PanelHelp = PanelHelp;
    function start() {
        if (!window.panelHelp) window.panelHelp = new PanelHelp(document, window);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once: true});
    else start();
}());
