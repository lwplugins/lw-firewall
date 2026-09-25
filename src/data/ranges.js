/**
 * [ min, max ] of an integer option, from meta.ranges (the OptionSchema
 * ranges the server enforces), so the UI never limits more strictly.
 *
 * @param {Object} meta Settings meta.
 * @param {string} key  Option key.
 * @return {Array} [ min, max ] (undefined bounds when unknown).
 */
export function rangeOf( meta, key ) {
	const range = meta?.ranges?.[ key ];
	return range ? [ range.min, range.max ] : [];
}
