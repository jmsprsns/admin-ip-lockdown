/**
 * Content Powered > Admin IP Lockdown page behaviour. Only loaded on that page.
 *
 * Tabs, the allowed-list rows (add, remove, "Add my IP", the type icon),
 * a warning when the lockdown is switched on without your own address on
 * the list, and confirmations for the buttons that end access or clear the
 * log. admin_ip_lockdown_admin comes from PHP (see
 * Admin_IP_Lockdown_Admin::enqueue_assets). The server checks everything
 * again on save; this only makes the page easier to use.
 */

/* global admin_ip_lockdown_admin */
( function () {
	'use strict';

	var data = window.admin_ip_lockdown_admin;

	document.addEventListener( 'DOMContentLoaded', function () {
		if ( typeof data === 'undefined' ) {
			return;
		}

		var form = document.querySelector( '.ailock-form' );

		initTabs( form );
		initEntries();
		initConfirms();
	} );

	// Tabs ---------------------------------------------------------------------

	function initTabs( form ) {
		var tabs = document.querySelectorAll( '[data-ailock-tab]' );
		var panels = document.querySelectorAll( '[data-ailock-panel]' );
		var referer = form ? form.querySelector( 'input[name="_wp_http_referer"]' ) : null;
		var refererBase = referer ? referer.value.split( '#' )[ 0 ] : '';

		function show( id ) {
			var found = false;

			tabs.forEach( function ( tab ) {
				var active = tab.getAttribute( 'data-ailock-tab' ) === id;

				found = found || active;
				tab.classList.toggle( 'is-active', active );
				tab.setAttribute( 'aria-selected', active ? 'true' : 'false' );
			} );

			if ( ! found && tabs.length ) {
				show( tabs[ 0 ].getAttribute( 'data-ailock-tab' ) );
				return;
			}

			panels.forEach( function ( panel ) {
				panel.hidden = panel.getAttribute( 'data-ailock-panel' ) !== id;
			} );

			// Come back to this tab after saving.
			if ( referer ) {
				referer.value = refererBase + '#' + id;
			}
		}

		tabs.forEach( function ( tab ) {
			tab.addEventListener( 'click', function ( event ) {
				var id = tab.getAttribute( 'data-ailock-tab' );

				event.preventDefault();
				show( id );
				history.replaceState( null, '', '#' + id );
			} );
		} );

		window.addEventListener( 'hashchange', function () {
			show( window.location.hash.replace( '#', '' ) );
		} );

		show( window.location.hash.replace( '#', '' ) );
	}

	// Allowed list ---------------------------------------------------------------

	function detectType( value ) {
		value = value.trim().toLowerCase();

		if ( ! value ) {
			return 'ip';
		}

		if ( /^[a-z][a-z0-9+.-]*:\/\//.test( value ) ) {
			return 'host';
		}

		if ( value.indexOf( '/' ) !== -1 || value.indexOf( '*' ) !== -1 ) {
			return 'range';
		}

		if ( value.indexOf( ':' ) !== -1 && ! /[g-z]/.test( value ) ) {
			return 'ip';
		}

		return /^[0-9.]+$/.test( value ) ? 'ip' : 'host';
	}

	function initEntries() {
		var list = document.querySelector( '[data-ailock-entries]' );
		var template = document.querySelector( '[data-ailock-template]' );
		var empty = document.querySelector( '[data-ailock-empty]' );
		var addButton = document.querySelector( '[data-ailock-add]' );
		var mineButton = document.querySelector( '[data-ailock-add-mine]' );
		var master = document.querySelector( '[data-ailock-enabled]' );
		var warning = document.querySelector( '[data-ailock-not-listed]' );
		var icons = {};
		var counter = Date.now();

		if ( ! list || ! template ) {
			return;
		}

		document.querySelectorAll( '[data-ailock-icon]' ).forEach( function ( icon ) {
			icons[ icon.getAttribute( 'data-ailock-icon' ) ] = icon.innerHTML;
		} );

		function rows() {
			return list.querySelectorAll( '[data-ailock-entry]' );
		}

		function listed() {
			var found = false;

			rows().forEach( function ( row ) {
				var value = row.querySelector( '[data-ailock-value]' ).value.trim().toLowerCase();

				found = found || ( value && ( value === data.myIp || value === data.myEntry ) );
			} );

			return found;
		}

		function refresh() {
			if ( empty ) {
				empty.hidden = rows().length > 0;
			}

			if ( mineButton ) {
				mineButton.hidden = listed();
			}

			if ( warning && master ) {
				var show = master.checked && ! data.myAllowed && ! listed();

				warning.hidden = ! show;
				warning.querySelector( 'span' ).textContent = show ? data.i18n.notListed : '';
			}
		}

		function setIcon( row ) {
			var input = row.querySelector( '[data-ailock-value]' );
			var holder = row.querySelector( '[data-ailock-type-icon]' );
			var type = detectType( input.value );

			if ( holder && icons[ type ] && holder.getAttribute( 'data-type' ) !== type ) {
				holder.innerHTML = icons[ type ];
				holder.setAttribute( 'data-type', type );
			}
		}

		function addRow( value, label ) {
			var html = template.innerHTML.replace( /__i__/g, 'n' + ( counter++ ) );
			var holder = document.createElement( 'div' );
			var row;

			holder.innerHTML = html.trim();
			row = holder.firstElementChild;
			list.insertBefore( row, empty );

			if ( value ) {
				row.querySelector( '[data-ailock-value]' ).value = value;
			}

			if ( label ) {
				row.querySelector( '[data-ailock-label]' ).value = label;
			}

			setIcon( row );
			refresh();

			return row;
		}

		list.addEventListener( 'input', function ( event ) {
			var row = event.target.closest( '[data-ailock-entry]' );

			if ( row && event.target.hasAttribute( 'data-ailock-value' ) ) {
				setIcon( row );
				refresh();
			}
		} );

		list.addEventListener( 'click', function ( event ) {
			var button = event.target.closest( '[data-ailock-remove]' );

			if ( button ) {
				event.preventDefault();
				button.closest( '[data-ailock-entry]' ).remove();
				refresh();
			}
		} );

		if ( addButton ) {
			addButton.addEventListener( 'click', function () {
				addRow( '', '' ).querySelector( '[data-ailock-value]' ).focus();
			} );
		}

		if ( mineButton ) {
			mineButton.addEventListener( 'click', function () {
				var row = addRow( data.myEntry, data.i18n.myLabel );

				row.querySelector( '[data-ailock-label]' ).focus();
				row.classList.add( 'is-new' );
			} );
		}

		if ( master ) {
			master.addEventListener( 'change', refresh );
		}

		rows().forEach( setIcon );
		refresh();
	}

	// Confirmations ----------------------------------------------------------------

	function initConfirms() {
		document.querySelectorAll( '[data-ailock-confirm]' ).forEach( function ( link ) {
			link.addEventListener( 'click', function ( event ) {
				var key = link.getAttribute( 'data-ailock-confirm' ) + 'Confirm';

				if ( data.i18n[ key ] && ! window.confirm( data.i18n[ key ] ) ) {
					event.preventDefault();
				}
			} );
		} );
	}
} )();
