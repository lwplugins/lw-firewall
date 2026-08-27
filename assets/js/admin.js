/**
 * LW Firewall - Admin JavaScript
 *
 * @package LightweightPlugins\Firewall
 */

(function () {
	'use strict';

	/**
	 * Initialize settings page tabs.
	 */
	function initTabs() {
		var tabLinks  = document.querySelectorAll( '.lw-firewall-tabs a' );
		var tabPanels = document.querySelectorAll( '.lw-firewall-tab-panel' );

		if ( ! tabLinks.length || ! tabPanels.length) {
			return;
		}

		var hash     = window.location.hash.substring( 1 );
		var firstTab = tabLinks[0].getAttribute( 'href' ).substring( 1 );
		var validTab = false;

		tabLinks.forEach(
			function (link) {
				if (link.getAttribute( 'href' ).substring( 1 ) === hash) {
					validTab = true;
				}
			}
		);

		activateTab( validTab ? hash : firstTab );

		tabLinks.forEach(
			function (link) {
				link.addEventListener(
					'click',
					function (e) {
						e.preventDefault();
						var tabId = this.getAttribute( 'href' ).substring( 1 );
						activateTab( tabId );
						history.replaceState( null, '', '#' + tabId );
					}
				);
			}
		);

		// Preserve active tab on form submit.
		var form = document.querySelector( '.lw-firewall-settings' );
		if (form) {
			form = form.closest( 'form' );
		}
		if (form) {
			form.addEventListener(
				'submit',
				function () {
					var activeLink = document.querySelector( '.lw-firewall-tabs a.active' );
					if ( ! activeLink) {
						return;
					}
					var tabId    = activeLink.getAttribute( 'href' ).substring( 1 );
					var tabInput = form.querySelector( 'input[name="lw_firewall_active_tab"]' );
					if (tabInput) {
						tabInput.value = tabId;
					}
				}
			);
		}

		function activateTab(tabId) {
			tabLinks.forEach(
				function (link) {
					var linkTabId = link.getAttribute( 'href' ).substring( 1 );
					if (linkTabId === tabId) {
						link.classList.add( 'active' );
					} else {
						link.classList.remove( 'active' );
					}
				}
			);

			tabPanels.forEach(
				function (panel) {
					if (panel.id === 'tab-' + tabId) {
						panel.classList.add( 'active' );
					} else {
						panel.classList.remove( 'active' );
					}
				}
			);
		}
	}

	/**
	 * Automatic Bans table: search, reason filters and paging.
	 *
	 * All rows are rendered by PHP and filtered here. The table sits inside the
	 * settings form, so a real ?paged=2 link would navigate away and discard
	 * unsaved settings on the other tabs.
	 */
	function initBans() {
		var root = document.querySelector( '[data-lw-bans]' );
		if ( ! root) {
			return;
		}

		var PER_PAGE = 20;
		var rows     = Array.prototype.slice.call( root.querySelectorAll( '[data-lw-ban-row]' ) );
		var search   = root.querySelector( '[data-lw-ban-search]' );
		var pager    = root.querySelector( '[data-lw-ban-pager]' );
		var bulk     = root.querySelector( '[data-lw-ban-bulk]' );
		var selcount = root.querySelector( '[data-lw-ban-selcount]' );
		var checkAll = root.querySelector( '[data-lw-ban-all]' );
		var nomatch  = root.querySelector( '.lw-bans-nomatch' );
		var chips    = Array.prototype.slice.call( root.querySelectorAll( '[data-lw-ban-filter]' ) );

		var filter = 'all';
		var query  = '';
		var page   = 1;

		function matches(row) {
			if (filter === 'inactive' && row.getAttribute( 'data-active' ) === '1') {
				return false;
			}
			if (filter !== 'all' && filter !== 'inactive' && row.getAttribute( 'data-reason' ) !== filter) {
				return false;
			}
			if (query && row.getAttribute( 'data-ip' ).indexOf( query ) === -1) {
				return false;
			}
			return true;
		}

		function selected() {
			return rows.filter(
				function (row) {
					var cb = row.querySelector( '[data-lw-ban-check]' );
					return cb && cb.checked;
				}
			);
		}

		function renderPager(total, pages) {
			var out = '<span class="lw-bans-count">' + total + '</span>';
			out    += '<button type="button" data-page="' + (page - 1) + '"' + (page === 1 ? ' disabled' : '') + '>&lsaquo;</button>';

			var shown = [];
			for (var p = 1; p <= pages; p++) {
				if (p === 1 || p === pages || Math.abs( p - page ) <= 1) {
					shown.push( p );
				}
			}

			var last = 0;
			shown.forEach(
				function (p) {
					if (p - last > 1) {
						out += '<span class="lw-bans-gap">&hellip;</span>';
					}
					out += '<button type="button" data-page="' + p + '"' + (p === page ? ' aria-current="page"' : '') + '>' + p + '</button>';
					last = p;
				}
			);

			out            += '<button type="button" data-page="' + (page + 1) + '"' + (page === pages ? ' disabled' : '') + '>&rsaquo;</button>';
			pager.innerHTML = out;
		}

		function render() {
			var visible = rows.filter( matches );
			var pages   = Math.max( 1, Math.ceil( visible.length / PER_PAGE ) );

			if (page > pages) {
				page = pages;
			}

			var start = (page - 1) * PER_PAGE;
			var end   = start + PER_PAGE;

			rows.forEach(
				function (row) {
					row.hidden = true;
				}
			);

			visible.slice( start, end ).forEach(
				function (row) {
					row.hidden = false;
				}
			);

			if (nomatch) {
				nomatch.hidden = visible.length > 0;
			}

			renderPager( visible.length, pages );

			var picked           = selected().length;
			bulk.disabled        = picked === 0;
			selcount.textContent = picked > 0 ? picked : '';
			checkAll.checked     = false;
		}

		chips.forEach(
			function (chip) {
				chip.addEventListener(
					'click',
					function () {
						chips.forEach(
							function (other) {
								other.setAttribute( 'aria-pressed', 'false' );
							}
						);
						chip.setAttribute( 'aria-pressed', 'true' );
						filter = chip.getAttribute( 'data-lw-ban-filter' );
						page   = 1;
						render();
					}
				);
			}
		);

		if (search) {
			search.addEventListener(
				'input',
				function () {
					query = this.value.trim();
					page  = 1;
					render();
				}
			);
		}

		pager.addEventListener(
			'click',
			function (e) {
				var button = e.target.closest( 'button[data-page]' );
				if ( ! button || button.disabled) {
					return;
				}
				page = parseInt( button.getAttribute( 'data-page' ), 10 );
				render();
			}
		);

		root.addEventListener(
			'change',
			function (e) {
				if ( ! e.target.matches( '[data-lw-ban-check]' )) {
					return;
				}
				var picked           = selected().length;
				bulk.disabled        = picked === 0;
				selcount.textContent = picked > 0 ? picked : '';
			}
		);

		checkAll.addEventListener(
			'change',
			function () {
				rows.forEach(
					function (row) {
						if (row.hidden) {
							return;
						}
						var cb = row.querySelector( '[data-lw-ban-check]' );
						if (cb) {
							cb.checked = checkAll.checked;
						}
					}
				);
				var picked           = selected().length;
				bulk.disabled        = picked === 0;
				selcount.textContent = picked > 0 ? picked : '';
			}
		);

		render();
	}

	function init() {
		initTabs();
		initBans();
	}

	if (document.readyState === 'loading') {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
})();
