/**
 * Centralized Iconify icon map for the Rakshak Security Dashboard.
 * All icons come from @iconify/react with Fluent UI Filled (fluent) + Noto sets
 * so they render as rich, colorful SVG images — not plain outline symbols.
 *
 * Usage:
 *   import { Icon } from '@iconify/react';
 *   import { IC } from '../utils/icons';
 *   <Icon icon={IC.shield} width={28} height={28} />
 */

export const IC = {
  // ── Navigation ──────────────────────────────────────────────────────────────
  dashboard:   'fluent:grid-28-filled',
  vulns:       'fluent:bug-24-filled',
  simLab:      'fluent:hat-graduation-24-filled',
  logout:      'fluent:sign-out-24-filled',
  settings:    'fluent:settings-24-filled',
  menu:        'fluent:line-horizontal-3-24-filled',
  close:       'fluent:dismiss-24-filled',
  bell:        'fluent:alert-24-filled',
  search:      'fluent:search-24-filled',
  back:        'fluent:arrow-left-24-filled',

  // ── Service Cards ────────────────────────────────────────────────────────────
  phishing:    'fluent:mail-alert-24-filled',
  fileScanner: 'fluent:document-search-24-filled',
  secAudit:    'fluent:clipboard-checkmark-24-filled',
  password:    'fluent:key-24-filled',
  website:     'fluent:globe-shield-24-filled',
  shield:      'fluent:shield-checkmark-24-filled',
  shieldAlert: 'fluent:shield-error-24-filled',

  // ── Status / Common ──────────────────────────────────────────────────────────
  checkCircle: 'fluent:checkmark-circle-24-filled',
  xCircle:     'fluent:dismiss-circle-24-filled',
  warning:     'fluent:warning-24-filled',
  info:        'fluent:info-24-filled',
  clock:       'fluent:clock-24-filled',
  refresh:     'fluent:arrow-counterclockwise-24-filled',
  chevRight:   'fluent:chevron-right-24-filled',
  chevDown:    'fluent:chevron-down-24-filled',
  star:        'fluent:star-24-filled',
  trophy:      'fluent:trophy-24-filled',
  sparkles:    'fluent:sparkle-24-filled',
  lock:        'fluent:lock-closed-24-filled',
  eye:         'fluent:eye-24-filled',
  eyeOff:      'fluent:eye-off-24-filled',
  copy:        'fluent:copy-24-filled',
  check:       'fluent:checkmark-24-filled',
  play:        'fluent:play-circle-24-filled',
  rotate:      'fluent:arrow-rotate-counterclockwise-24-filled',
  layers:      'fluent:layer-24-filled',
  activity:    'fluent:pulse-24-filled',
  server:      'fluent:server-24-filled',
  link:        'fluent:link-24-filled',
  externalLink:'fluent:open-24-filled',
  upload:      'fluent:cloud-arrow-up-24-filled',
  target:      'fluent:target-24-filled',
  zap:         'fluent:flash-24-filled',
  chart:       'fluent:data-bar-vertical-24-filled',
  radar:       'fluent:wifi-24-filled',
  bookOpen:    'fluent:book-open-24-filled',
  users:       'fluent:people-24-filled',
  creditCard:  'fluent:payment-24-filled',
  network:     'fluent:network-24-filled',
  terminal:    'fluent:window-console-20-filled',
  grad:        'fluent:hat-graduation-24-filled',
  siren:       'fluent:vehicle-car-24-filled',

  // ── Simulation Lab Modules ───────────────────────────────────────────────────
  simPhishing: 'noto:fishing-pole',
  simPassword: 'noto:key',
  simMalware:  'noto:bug',
  simNetwork:  'noto:satellite-antenna',
  simWebSec:   'noto:globe-showing-asia-australia',
  simPrivacy:  'noto:locked',
  simIncident: 'noto:police-car-light',

  // ── Security Levels ──────────────────────────────────────────────────────────
  critical:    'fluent:error-circle-24-filled',
  high:        'fluent:warning-24-filled',
  medium:      'fluent:info-24-filled',
  low:         'fluent:checkmark-circle-24-filled',

  // ── File Types (Malware Lab) ─────────────────────────────────────────────────
  filePdf:     'fluent:document-pdf-24-filled',
  fileExe:     'fluent:app-generic-24-filled',
  fileZip:     'fluent:folder-zip-24-filled',
  fileImg:     'fluent:image-24-filled',
  fileDoc:     'fluent:document-word-24-filled',

  // ── Network ──────────────────────────────────────────────────────────────────
  wifi:        'fluent:wifi-4-24-filled',
  wifiOff:     'fluent:wifi-off-24-filled',
  vpn:         'fluent:shield-person-24-filled',

};
