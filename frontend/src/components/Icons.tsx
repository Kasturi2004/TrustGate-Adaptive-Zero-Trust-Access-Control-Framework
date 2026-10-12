import type { ReactNode, SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };
function Icon({
  children,
  size = 24,
  ...props
}: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {children}
    </svg>
  );
}
export const Activity = (props: IconProps) => (
  <Icon {...props}>
    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
  </Icon>
);
export const AlertCircle = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 8v4m0 4h.01" />
  </Icon>
);
export const AlertTriangle = (props: IconProps) => (
  <Icon {...props}>
    <path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z" />
    <path d="M12 9v4m0 4h.01" />
  </Icon>
);
export const ArrowDownRight = (props: IconProps) => (
  <Icon {...props}>
    <path d="M7 7 17 17M17 7v10H7" />
  </Icon>
);
export const ArrowLeft = (props: IconProps) => (
  <Icon {...props}>
    <path d="M19 12H5m7 7-7-7 7-7" />
  </Icon>
);
export const ArrowRight = (props: IconProps) => (
  <Icon {...props}>
    <path d="M5 12h14m-7-7 7 7-7 7" />
  </Icon>
);
export const ArrowUpRight = (props: IconProps) => (
  <Icon {...props}>
    <path d="M7 17 17 7M7 7h10v10" />
  </Icon>
);
export const Bell = (props: IconProps) => (
  <Icon {...props}>
    <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 12h4" />
  </Icon>
);
export const ChevronDown = (props: IconProps) => (
  <Icon {...props}>
    <path d="m6 9 6 6 6-6" />
  </Icon>
);
export const ChevronLeft = (props: IconProps) => (
  <Icon {...props}>
    <path d="m15 18-6-6 6-6" />
  </Icon>
);
export const ChevronRight = (props: IconProps) => (
  <Icon {...props}>
    <path d="m9 18 6-6-6-6" />
  </Icon>
);
export const CircleHelp = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M9.6 9a2.5 2.5 0 1 1 4.3 1.7c-1 .9-1.9 1.2-1.9 2.8m0 3h.01" />
  </Icon>
);
export const ChartBars = (props: IconProps) => (
  <Icon {...props}>
    <path d="M4 19V9m5 10V5m5 14v-7m5 7V3" />
  </Icon>
);
export const CalendarDays = (props: IconProps) => (
  <Icon {...props}>
    <rect x="3" y="5" width="18" height="16" rx="2" />
    <path d="M16 3v4M8 3v4M3 10h18M8 14h.01M12 14h.01M16 14h.01M8 17h.01M12 17h.01" />
  </Icon>
);
export const Computer = (props: IconProps) => (
  <Icon {...props}>
    <rect x="3" y="4" width="18" height="13" rx="2" />
    <path d="M8 21h8m-4-4v4" />
  </Icon>
);
export const Eye = (props: IconProps) => (
  <Icon {...props}>
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
    <circle cx="12" cy="12" r="3" />
  </Icon>
);
export const EyeOff = (props: IconProps) => (
  <Icon {...props}>
    <path d="M3 3l18 18M10.6 10.6A3 3 0 0 0 12 15a3 3 0 0 0 2.4-4.4M9.9 5.1A10.8 10.8 0 0 1 12 5c6.5 0 10 7 10 7a18.3 18.3 0 0 1-2.2 3.1M6.1 6.1A18 18 0 0 0 2 12s3.5 7 10 7a10.4 10.4 0 0 0 4.2-.9" />
  </Icon>
);
export const Clock3 = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Icon>
);
export const FileSearch = (props: IconProps) => (
  <Icon {...props}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h8m0-20v6h6m-6-6 6 6m-8 8 5 5m-2-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z" />
  </Icon>
);
export const Fingerprint = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 11a2 2 0 0 0-2 2c0 4-.5 6-1.5 8M14 13c0 3-.2 5.4-1 8m4-8c0 2.5.5 4.5 1.5 6M8 16c-.3 1.8-.7 3.4-1.5 5M6 13a6 6 0 0 1 12 0M4 13a8 8 0 0 1 16 0M12 5a8 8 0 0 1 8 8" />
  </Icon>
);
export const GitBranch = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="6" cy="3" r="2" />
    <circle cx="6" cy="21" r="2" />
    <circle cx="18" cy="6" r="2" />
    <path d="M6 5v14m12-11a9 9 0 0 1-9 9" />
  </Icon>
);
export const LayoutDashboard = (props: IconProps) => (
  <Icon {...props}>
    <rect x="3" y="3" width="8" height="8" rx="1.5" />
    <rect x="13" y="3" width="8" height="5" rx="1.5" />
    <rect x="13" y="10" width="8" height="11" rx="1.5" />
    <rect x="3" y="13" width="8" height="8" rx="1.5" />
  </Icon>
);
export const LoaderCircle = (props: IconProps) => (
  <Icon {...props}>
    <path d="M21 12a9 9 0 1 1-6.2-8.6" />
  </Icon>
);
export const LogOut = (props: IconProps) => (
  <Icon {...props}>
    <path d="M10 17l5-5-5-5m5 5H3m9-9h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6" />
  </Icon>
);
export const MapPin = (props: IconProps) => (
  <Icon {...props}>
    <path d="M20 10c0 5-8 12-8 12S4 15 4 10a8 8 0 1 1 16 0Z" />
    <circle cx="12" cy="10" r="2.5" />
  </Icon>
);
export const Plus = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 5v14M5 12h14" />
  </Icon>
);
export const Menu = (props: IconProps) => (
  <Icon {...props}>
    <path d="M4 6h16M4 12h16M4 18h16" />
  </Icon>
);
export const RefreshCw = (props: IconProps) => (
  <Icon {...props}>
    <path d="M20 7v5h-5M4 17v-5h5m-4-2a7 7 0 0 1 12-4l3 3M4 15l3 3a7 7 0 0 0 12-4" />
  </Icon>
);
export const Shield = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
  </Icon>
);
export const ShieldAlert = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
    <path d="M12 8v4m0 4h.01" />
  </Icon>
);
export const ShieldCheck = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
    <path d="m9 12 2 2 4-4" />
  </Icon>
);
export const ShieldX = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
    <path d="m9 9 6 6m0-6-6 6" />
  </Icon>
);
export const Sliders = (props: IconProps) => (
  <Icon {...props}>
    <path d="M4 6h9m4 0h3M4 18h3m4 0h9M13 3v6M7 15v6m7-6h-3" />
    <circle cx="15" cy="6" r="2" />
    <circle cx="9" cy="18" r="2" />
  </Icon>
);
export const Users = (props: IconProps) => (
  <Icon {...props}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2m6-10a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm6-7.8a4 4 0 0 1 0 7.6m2 4.2a4 4 0 0 1 2 3.5V21" />
  </Icon>
);
export const X = (props: IconProps) => (
  <Icon {...props}>
    <path d="m18 6-12 12M6 6l12 12" />
  </Icon>
);
