/**
 * Loading placeholder of the section (WPDS Skeleton, never a spinner).
 */
/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import {
	SkeletonRegion,
	SkeletonText,
	SkeletonBlock,
} from '../components/skeleton';

/**
 * @param {Object} props
 * @param {number} props.rows Row count.
 */
export default function Loading( { rows = 3 } ) {
	return (
		<SkeletonRegion
			className="lwfw-2fa-skeleton"
			label={ __( 'Loading two-factor settings…', 'lw-firewall' ) }
		>
			{ Array.from( { length: rows }, ( _, index ) => (
				<span key={ index } className="lwfw-2fa-row">
					<SkeletonText width="140px" />
					<span className="lwfw-2fa-row__body">
						<SkeletonText width="45%" />
						<SkeletonBlock width={ 180 } height={ 40 } />
					</span>
				</span>
			) ) }
		</SkeletonRegion>
	);
}
