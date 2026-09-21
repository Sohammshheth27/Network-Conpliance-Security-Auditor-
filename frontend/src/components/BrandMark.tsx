import { useId } from 'react';

/**
 * The MERIDIAN mark: eight meridians converging on a pole.
 *
 * A meridian is the fixed line a position is measured against, which is what
 * this tool does to a configuration -- so the coloured element is the
 * reference, not decoration.
 *
 * WHY THE LINES ARE CUT OUT OF A DISC RATHER THAN DRAWN AS PETALS
 * ---------------------------------------------------------------
 * The obvious way to draw a radial mark is eight petals radiating from the
 * centre. Rendered at 16px that is a four-point sparkle -- indistinguishable
 * from the icon every product now puts on its AI button, and the last thing a
 * compliance auditor's mark should borrow. Adding a solid pole disc did not
 * save it; the disc is swallowed by the petal bases.
 *
 * Carving the meridians OUT of a solid disc fixes it, because the silhouette
 * stops depending on the detail. The outline is a circle at every size; the
 * radial structure is what you gain as the mark grows. Nothing thin exists in
 * the silhouette, so nothing can shatter. Verified legible down to 14px.
 *
 * The cuts are clipped to the disc. Without the clip they overhang the rim as
 * blue nubs, which is a different mark at 96px than at 16px.
 */

/** One meridian, pointing north. The rest are this, rotated. */
const MERIDIAN = 'M12 9.4 Q14.4 5.76 13.5 0.2 L10.5 0.2 Q9.6 5.76 12 9.4 Z';

const ANGLES = [0, 45, 90, 135, 180, 225, 270, 315];

const RADIUS = 10.4;

type Props = {
  /** The sphere. Set it to contrast with whatever it sits on. */
  disc: string;
  /** The meridians. Signal Blue unless there is a reason. */
  cut?: string;
  className?: string;
  size?: number;
};

export default function BrandMark({
  disc,
  cut = '#006bff',
  className,
  size,
}: Props) {
  // Two instances render on the login page at once. A fixed clip-path id
  // would collide and the second mark would clip against the first.
  const clipId = `meridian-clip-${useId().replace(/:/g, '')}`;

  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      aria-hidden="true"
    >
      <clipPath id={clipId}>
        <circle cx="12" cy="12" r={RADIUS} />
      </clipPath>
      <circle cx="12" cy="12" r={RADIUS} fill={disc} />
      <g clipPath={`url(#${clipId})`} fill={cut}>
        {ANGLES.map((a) => (
          <path key={a} d={MERIDIAN} transform={`rotate(${a} 12 12)`} />
        ))}
      </g>
    </svg>
  );
}
