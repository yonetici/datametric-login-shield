/**
 * Datametric Login Shield — admin behaviours.
 */
( function () {
	'use strict';

	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest( '.dls-copy' );
		if ( ! button ) {
			return;
		}

		event.preventDefault();

		var value = button.getAttribute( 'data-clipboard' ) || '';
		var label = button.textContent;
		var done = function () {
			button.textContent =
				( window.dlsAdmin && window.dlsAdmin.copied ) || 'Copied!';
			setTimeout( function () {
				button.textContent = label;
			}, 1500 );
		};

		if ( navigator.clipboard && navigator.clipboard.writeText ) {
			navigator.clipboard.writeText( value ).then( done ).catch( function () {
				fallbackCopy( value );
				done();
			} );
		} else {
			fallbackCopy( value );
			done();
		}
	} );

	function fallbackCopy( value ) {
		var field = document.createElement( 'textarea' );
		field.value = value;
		field.setAttribute( 'readonly', '' );
		field.style.position = 'absolute';
		field.style.left = '-9999px';
		document.body.appendChild( field );
		field.select();
		try {
			document.execCommand( 'copy' );
		} catch ( e ) {}
		document.body.removeChild( field );
	}
} )();
