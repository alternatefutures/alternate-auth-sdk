/**
 * The Alternate Clouds mark: the web app's `public/logo.svg`, inline so it
 * needs no asset pipeline. Filled with `currentColor` the way the app uses it
 * (white on dark surfaces, the button's text color on buttons).
 */

import * as React from 'react';

const PATH = 'M34.91,15.61h-15.61v5.32h12.79v3.18h-12.79v7.89h-4.17V12.22h19.78v3.39ZM18.07,9.14l-6.32,6.26h-5.39l-1.95,4.29H0L9.3,0h4.41l4.36,9.14ZM7.9,12.02h7.25l-3.64-7.93-3.61,7.93Z';

export interface MarkProps extends Omit<React.SVGProps<SVGSVGElement>, 'children'> {
  size?: number | string;
}

export function Mark({ size = 16, className, style, ...rest }: MarkProps) {
  return (
    <svg
      viewBox="0 0 35 32"
      width={size}
      height={size}
      aria-hidden="true"
      focusable="false"
      data-slot="mark"
      className={className}
      style={{ fill: 'currentColor', flexShrink: 0, ...style }}
      {...rest}
    >
      <path d={PATH} />
    </svg>
  );
}
