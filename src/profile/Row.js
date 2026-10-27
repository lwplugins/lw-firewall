/**
 * One labelled row, in the rhythm of the core profile form table.
 */

/**
 * @param {Object}  props
 * @param {string}  props.title    Row label.
 * @param {Element} props.children Content.
 */
export default function Row( { title, children } ) {
	return (
		<div className="lwfw-2fa-row">
			<h3 className="lwfw-2fa-row__title">{ title }</h3>
			<div className="lwfw-2fa-row__body">{ children }</div>
		</div>
	);
}
