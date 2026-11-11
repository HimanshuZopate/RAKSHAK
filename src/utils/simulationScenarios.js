// ─── Cybersecurity Simulation Lab — Scenario Content ────────────────────────
// All scenarios use fictional names, domains, and organizations.
// Everything is clearly marked as SIMULATED EDUCATIONAL CONTENT.

export const SIMULATIONS = [
  {
    id: 'phishing',
    title: 'Phishing & Social Engineering Lab',
    icon: 'Mail',
    color: 'from-rose-600 to-orange-500',
    shadow: 'shadow-rose-500/25',
    border: 'border-rose-500/30',
    accentText: 'text-rose-400',
    difficulty: 'Beginner',
    duration: '10–15 min',
    objectives: [
      'Identify warning signs in phishing emails',
      'Recognize social engineering tactics',
      'Practice safe reporting procedures',
    ],
    description: 'Learn how attackers manipulate people through fake emails, SMS messages, and impersonation.',
  },
  {
    id: 'password',
    title: 'Password Security Lab',
    icon: 'KeyRound',
    color: 'from-cyan-500 to-blue-600',
    shadow: 'shadow-cyan-500/25',
    border: 'border-cyan-500/30',
    accentText: 'text-cyan-400',
    difficulty: 'Beginner',
    duration: '8–12 min',
    objectives: [
      'Understand password strength factors',
      'Learn passphrase advantages',
      'Explore MFA and password managers',
    ],
    description: 'Discover why password security matters and practice creating stronger credentials.',
  },
  {
    id: 'malware',
    title: 'Malware & Suspicious File Lab',
    icon: 'Bug',
    color: 'from-violet-600 to-purple-700',
    shadow: 'shadow-violet-500/25',
    border: 'border-violet-500/30',
    accentText: 'text-violet-400',
    difficulty: 'Intermediate',
    duration: '10–15 min',
    objectives: [
      'Recognize dangerous file types',
      'Understand double-extension tricks',
      'Practice safe file handling procedures',
    ],
    description: 'Understand how malicious files spread and practice safe file inspection workflows.',
  },
  {
    id: 'network',
    title: 'Network Security Lab',
    icon: 'Wifi',
    color: 'from-emerald-500 to-teal-600',
    shadow: 'shadow-emerald-500/25',
    border: 'border-emerald-500/30',
    accentText: 'text-emerald-400',
    difficulty: 'Intermediate',
    duration: '12–18 min',
    objectives: [
      'Compare public vs private network risks',
      'Understand HTTPS and TLS basics',
      'Learn firewall and VPN fundamentals',
    ],
    description: 'Explore network security concepts through an interactive simulated topology.',
  },
  {
    id: 'websec',
    title: 'Web Security Awareness Lab',
    icon: 'Globe',
    color: 'from-blue-500 to-indigo-600',
    shadow: 'shadow-blue-500/25',
    border: 'border-blue-500/30',
    accentText: 'text-blue-400',
    difficulty: 'Intermediate',
    duration: '12–15 min',
    objectives: [
      'Understand HTTPS and certificate basics',
      'Recognize SQL injection concepts safely',
      'Learn about input validation',
    ],
    description: 'Explore how websites are attacked and how developers protect them.',
  },
  {
    id: 'privacy',
    title: 'Digital Privacy & Device Protection',
    icon: 'Shield',
    color: 'from-amber-500 to-yellow-600',
    shadow: 'shadow-amber-500/25',
    border: 'border-amber-500/30',
    accentText: 'text-amber-400',
    difficulty: 'Beginner',
    duration: '8–10 min',
    objectives: [
      'Audit app permissions effectively',
      'Enable and understand MFA',
      'Learn browser privacy controls',
    ],
    description: 'Learn to protect your everyday devices, accounts, and digital privacy.',
  },
  {
    id: 'incident',
    title: 'Incident Response Simulator',
    icon: 'Siren',
    color: 'from-red-600 to-rose-700',
    shadow: 'shadow-red-500/25',
    border: 'border-red-500/30',
    accentText: 'text-red-400',
    difficulty: 'Advanced',
    duration: '15–20 min',
    objectives: [
      'Make real-time security decisions',
      'Practice incident containment steps',
      'Understand reporting procedures',
    ],
    description: 'Respond to realistic fictional security incidents and learn from each decision.',
  },
];

// ─── Phishing Simulation Scenarios ───────────────────────────────────────────

export const PHISHING_SCENARIOS = [
  {
    id: 'ph1',
    title: 'The Urgent Bank Alert',
    email: {
      from: 'security@nationalpankk-india.co.in',
      displayName: 'NationalPank Security Team',
      subject: '🚨 URGENT: Your account will be blocked in 24 hours',
      body: `Dear Valued Customer,

We have detected unusual activity on your account. Your account access will be SUSPENDED within 24 hours unless you verify your identity immediately.

Click the link below to verify your account now:
👉 http://secure-nationalpank-verify.foreignhost.xyz/login

Enter your:
• Account Number
• ATM PIN
• OTP from your registered mobile

Failure to verify will result in PERMANENT account closure.

— NationalPank Security Team
(This is an automated message. Do not reply.)`,
      redFlags: [
        { phrase: 'nationalpankk-india.co.in', reason: 'Misspelled domain — "pankk" not "bank"' },
        { phrase: 'nationalpank-verify.foreignhost.xyz', reason: 'Third-party domain, not a legitimate bank URL' },
        { phrase: 'URGENT', reason: 'Artificial urgency is a common manipulation tactic' },
        { phrase: 'ATM PIN', reason: 'Banks never ask for your PIN in any communication' },
        { phrase: 'OTP', reason: 'Never share OTPs — valid systems never ask for them' },
        { phrase: 'PERMANENT account closure', reason: 'Fear-based threat to pressure quick action' },
      ],
    },
    choices: [
      { id: 'a', text: 'Click the link and enter my details', correct: false, feedback: 'This is exactly what attackers want. The link leads to a fake page that steals your credentials.' },
      { id: 'b', text: 'Call the bank using the official number from their website', correct: true, feedback: 'Correct! Always verify using independently obtained contact information — never from the suspicious message itself.' },
      { id: 'c', text: 'Reply to the email asking if it is genuine', correct: false, feedback: 'Replying confirms your email is active. Always verify through official channels, not by responding.' },
      { id: 'd', text: 'Forward to a friend to check', correct: false, feedback: 'Sharing the message spreads the risk. Report it as spam and contact the bank directly.' },
    ],
  },
  {
    id: 'ph2',
    title: 'The Prize Winner SMS',
    email: {
      from: '+91-XXXXXXXX12 (Unknown Number)',
      displayName: 'KBC Prize Desk',
      subject: 'SMS Message',
      body: `Congratulations! You have been selected as the winner of ₹25,00,000 in the KBC Digital Lucky Draw 2024.

To claim your prize:
1. Send your full name and Aadhaar number
2. Pay a ₹500 processing fee to UPI: prize.kbc2024@fakebank
3. Share the OTP you receive for verification

Claim expires in 2 hours. Call: 9XXXXXXXXX

This is a SIMULATED scenario for educational purposes.`,
      redFlags: [
        { phrase: 'Unknown Number', reason: 'Legitimate prize notifications come from verified official channels' },
        { phrase: 'pay a ₹500 processing fee', reason: 'Advance fee fraud — legitimate prizes never require upfront payment' },
        { phrase: 'Send your full name and Aadhaar number', reason: 'Never share Aadhaar or identity details over SMS' },
        { phrase: 'Share the OTP', reason: 'OTPs are secret — sharing them gives access to your accounts' },
        { phrase: 'Claim expires in 2 hours', reason: 'Artificial time pressure forces poor decisions' },
      ],
    },
    choices: [
      { id: 'a', text: 'Pay the fee and share my Aadhaar to claim the prize', correct: false, feedback: 'This is an advance-fee fraud. You would lose money and expose sensitive identity information.' },
      { id: 'b', text: 'Ignore and block the number', correct: true, feedback: 'Correct! Unsolicited prize messages are almost always scams. Block and report the number.' },
      { id: 'c', text: 'Share my details but skip the payment', correct: false, feedback: 'Your Aadhaar and personal details can be used for identity theft even without the payment.' },
      { id: 'd', text: 'Visit the KBC official website to verify', correct: true, feedback: 'Also correct — checking through official verified sources is always a good approach.' },
    ],
  },
];

// ─── Network Security Simulation Data ────────────────────────────────────────

export const NETWORK_SCENARIOS = [
  {
    id: 'wifi1',
    type: 'wifi',
    name: 'AirportFreeWifi',
    security: 'Open (No Password)',
    encryption: 'None',
    risk: 'Critical',
    description: 'An open public network. All traffic is visible to anyone on the same network.',
    risks: ['Traffic interception by attackers', 'Man-in-the-middle attacks', 'Session hijacking on HTTP sites'],
    recommendations: ['Avoid sensitive activities', 'Use a VPN if you must connect', 'Prefer mobile data instead'],
  },
  {
    id: 'wifi2',
    type: 'wifi',
    name: 'HomeNetwork_Secure',
    security: 'WPA3-Personal',
    encryption: 'AES-256',
    risk: 'Low',
    description: 'A home network with strong WPA3 encryption and a unique password.',
    risks: ['Weak password could still be guessed', 'Outdated router firmware'],
    recommendations: ['Keep router firmware updated', 'Use a strong unique password', 'Enable guest network for visitors'],
  },
  {
    id: 'wifi3',
    type: 'wifi',
    name: 'CafeWiFi_Free',
    security: 'WPA2-Personal',
    encryption: 'AES',
    risk: 'Medium',
    description: 'A shared public network with a common password available to all customers.',
    risks: ['Other customers on same network', 'Password shared openly', 'No traffic isolation'],
    recommendations: ['Avoid banking or sensitive logins', 'Use HTTPS sites only', 'Use VPN for extra protection'],
  },
];

// ─── Incident Response Scenarios ─────────────────────────────────────────────

export const INCIDENT_SCENARIOS = [
  {
    id: 'inc1',
    title: 'Suspicious UPI Transaction',
    description: 'You receive an SMS: "₹15,000 debited from your account to UPI ID: prize.fund@fakebank. If not done by you, call 1800-XXXXXX immediately." You did NOT initiate this transaction.',
    icon: 'CreditCard',
    steps: [
      {
        question: 'What is your FIRST action?',
        choices: [
          { id: 'a', text: 'Call the number in the SMS', correct: false, feedback: 'The number in the SMS may be fake. Call only the official bank helpline from the back of your card or official website.' },
          { id: 'b', text: 'Call your bank\'s official helpline immediately', correct: true, feedback: 'Correct! Report unauthorized transactions to your official bank helpline immediately to freeze the account.' },
          { id: 'c', text: 'Wait to see if the money returns', correct: false, feedback: 'Every minute of delay reduces the chance of recovering funds. Act immediately.' },
          { id: 'd', text: 'Share your account details with the SMS number to investigate', correct: false, feedback: 'Never share account details. This is another phishing attempt using the fraudulent transaction as bait.' },
        ],
      },
      {
        question: 'Your bank asks you to file a report. Where should you report?',
        choices: [
          { id: 'a', text: 'National Cyber Crime Reporting Portal (cybercrime.gov.in)', correct: true, feedback: 'Correct! In India, report cyber financial fraud at cybercrime.gov.in or call 1930 (Cyber Crime Helpline).' },
          { id: 'b', text: 'Post on social media for public awareness', correct: false, feedback: 'Social media posting does not help recovery. Use official reporting channels.' },
          { id: 'c', text: 'Email the attacker demanding the money back', correct: false, feedback: 'Contacting the attacker achieves nothing and may confirm your vulnerability.' },
          { id: 'd', text: 'Only tell friends and family', correct: false, feedback: 'Official reporting is essential for investigation and potential fund recovery.' },
        ],
      },
    ],
  },
  {
    id: 'inc2',
    title: 'Suspicious Link Clicked',
    description: 'You accidentally clicked a link in a suspicious email on your work laptop. A warning appeared briefly, then a page asked for your work email and password.',
    icon: 'Link',
    steps: [
      {
        question: 'What should you do IMMEDIATELY?',
        choices: [
          { id: 'a', text: 'Enter credentials to check if the page is real', correct: false, feedback: 'Never enter credentials on a page reached through a suspicious link. This would compromise your account.' },
          { id: 'b', text: 'Disconnect from network and notify IT security', correct: true, feedback: 'Correct! Disconnecting limits potential damage. Your IT team needs to know immediately to contain the incident.' },
          { id: 'c', text: 'Run a quick Google search about the site', correct: false, feedback: 'The machine may already be compromised. Disconnect first, investigate after.' },
          { id: 'd', text: 'Close the browser and continue working', correct: false, feedback: 'The device may have been compromised. It needs proper inspection by security personnel.' },
        ],
      },
      {
        question: 'After notifying IT, what else should you do?',
        choices: [
          { id: 'a', text: 'Change your password from a DIFFERENT, clean device', correct: true, feedback: 'Correct! Change passwords from a trusted device since the compromised machine may have keyloggers.' },
          { id: 'b', text: 'Change your password on the same compromised machine', correct: false, feedback: 'The compromised machine may capture your new password too. Always use a clean device.' },
          { id: 'c', text: 'Nothing — IT will handle everything', correct: false, feedback: 'You should also change your credentials and enable MFA from a safe device.' },
          { id: 'd', text: 'Format the laptop yourself immediately', correct: false, feedback: 'Formatting destroys forensic evidence. Let IT security handle the investigation first.' },
        ],
      },
    ],
  },
];

// ─── Malware File Awareness Data ─────────────────────────────────────────────

export const SUSPICIOUS_FILE_SCENARIOS = [
  {
    name: 'Invoice_March2024.pdf.exe',
    extension: '.exe',
    displayedAs: 'PDF Document',
    mimeType: 'application/octet-stream',
    risk: 'Critical',
    explanation: 'This file uses a double extension trick. Windows hides known extensions by default, so "Invoice_March2024.pdf.exe" may display as "Invoice_March2024.pdf" — looking like a harmless PDF while actually being an executable.',
    safeAction: 'Never open. Report to IT. Delete from email.',
  },
  {
    name: 'Project_Report.docx',
    extension: '.docx',
    displayedAs: 'Word Document',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    risk: 'Medium',
    explanation: 'Office documents can contain macros (embedded scripts). If prompted to "Enable Content" or "Enable Macros" in a document from an unknown source, decline — macros can execute malicious code.',
    safeAction: 'Open in protected view. Never enable macros from untrusted sources.',
  },
  {
    name: 'free_antivirus_setup.zip',
    extension: '.zip',
    displayedAs: 'ZIP Archive',
    mimeType: 'application/zip',
    risk: 'High',
    explanation: 'Archives can bundle malicious executables. Attackers often rename malware as utility software. The contents are unknown until extracted, and extraction itself can trigger some malware.',
    safeAction: 'Scan before extracting. Verify the source. Prefer downloads from official vendors.',
  },
  {
    name: 'profile_photo.jpg',
    extension: '.jpg',
    displayedAs: 'JPEG Image',
    mimeType: 'image/jpeg',
    risk: 'Low',
    explanation: 'Images are generally low-risk but can occasionally exploit vulnerabilities in image viewers. Verify the file is actually an image (check file size and preview). Steganography can hide data in images but cannot execute it simply by viewing.',
    safeAction: 'Generally safe to view. Keep your image viewer updated.',
  },
];

export const DIFFICULTY_COLORS = {
  Beginner: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  Intermediate: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  Advanced: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
};
