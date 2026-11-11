import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowRight, CheckCircle2, ChevronDown, FileSearch, Globe2, KeyRound,
  LockKeyhole, Menu, MessageSquareWarning, Shield, ShieldCheck, Sparkles,
  Terminal, X, Zap,
} from 'lucide-react';

const services = [
  {
    icon: MessageSquareWarning,
    category: 'Detect',
    title: 'Phishing & Scam Detector',
    description: 'Analyze suspicious messages and URLs for common phishing indicators and scam patterns.',
    points: ['URL warning indicators', 'Message risk analysis', 'Actionable safety guidance'],
    href: '/phishing-detector',
    cta: 'Analyze a message',
  },
  {
    icon: KeyRound,
    category: 'Strengthen',
    title: 'Password Security Checker',
    description: 'Evaluate password strength and learn how to build stronger credentials privately in your browser.',
    points: ['Pattern detection', 'Passphrase guidance', 'Secure generation'],
    href: '/password-security',
    cta: 'Check password strength',
  },
  {
    icon: Globe2,
    category: 'Assess',
    title: 'Website Security Checker',
    description: 'Review basic HTTPS, TLS, and HTTP security-header configuration for a public website.',
    points: ['HTTPS availability', 'Certificate details', 'Header recommendations'],
    href: '/website-security',
    cta: 'Check a website',
  },
  {
    icon: FileSearch,
    category: 'Inspect',
    title: 'File Malware Scanner',
    description: 'Scan a supported file with malware and static-analysis engines, then review the findings clearly.',
    points: ['Temporary file handling', 'Dual-engine analysis', 'Finding summaries'],
    href: '/file-scanner',
    cta: 'Inspect a file',
  },
];

const faqs = [
  ['What is Rakshak?', 'Rakshak is a practical security toolkit that helps you investigate common online risks and build safer digital habits through guided tools and simulations.'],
  ['Does the password checker store my password?', 'The password analysis experience is designed to assess input locally in the browser. Never reuse a real password while experimenting with any security tool.'],
  ['Is the website checker a penetration test?', 'No. It checks selected public configuration signals such as HTTPS, TLS, and security headers. It cannot guarantee that a website is secure.'],
  ['Can beginners use the Simulation Lab?', 'Yes. The Simulation Lab provides guided, safe scenarios for learning about phishing, passwords, networks, files, and incident response.'],
  ['How is user data handled?', 'Inputs are handled according to each tool’s behavior. Avoid submitting secrets or sensitive personal data, and review the results before taking action.'],
];

const LandingPage = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [openFaq, setOpenFaq] = useState(0);
  const [activePreview, setActivePreview] = useState('phishing');

  const closeMenu = () => setMenuOpen(false);

  return (
    <main className="landing-page">
      <nav className="landing-nav" aria-label="Primary navigation">
        <a href="#home" className="landing-brand" onClick={closeMenu}>
          <span className="landing-brand-mark"><ShieldCheck size={21} /></span>
          <span>Rakshak</span>
        </a>
        <button className="landing-menu-button" onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle menu" aria-expanded={menuOpen}>
          {menuOpen ? <X size={22} /> : <Menu size={22} />}
        </button>
        <div className={`landing-links ${menuOpen ? 'is-open' : ''}`}>
          <a href="#home" onClick={closeMenu}>Home</a>
          <a href="#services" onClick={closeMenu}>Security Services</a>
          <a href="#simulations" onClick={closeMenu}>Simulation Lab</a>
          <a href="#how-it-works" onClick={closeMenu}>How It Works</a>
          <a href="#faq" onClick={closeMenu}>FAQ</a>
          <div className="landing-auth-links">
            <Link to="/login" className="landing-login" onClick={closeMenu}>Log in</Link>
            <Link to="/signup" className="landing-signup" onClick={closeMenu}>Sign up <ArrowRight size={15} /></Link>
          </div>
        </div>
      </nav>

      <section id="home" className="landing-hero">
        <div className="landing-grid-glow" />
        <div className="landing-hero-copy">
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} className="landing-eyebrow">
            <span className="status-dot" /> Your digital world. Better protected.
          </motion.div>
          <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0, delay: 0.08 }}>
            Master cybersecurity.<br /><span>Protect your digital life.</span>
          </motion.h1>
          <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0, delay: 0.16 }}>
            Discover digital threats, strengthen your security, and learn to stay safer online through practical tools and interactive simulations.
          </motion.p>
          <div className="landing-hero-actions">
            <a href="#services" className="landing-primary-button">Explore security tools <ArrowRight size={18} /></a>
            <Link to="/simulation-lab" className="landing-secondary-button"><Zap size={17} /> Enter Simulation Lab</Link>
          </div>
          <div className="landing-microcopy"><CheckCircle2 size={16} /> Learn. Practice. Detect. Protect.</div>
        </div>
        <motion.div initial={{ opacity: 0, scale: 0.92 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.2 }} className="landing-visual">
          <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" />
          <div className="visual-core"><Shield size={65} /><span>Rakshak</span><small>Security toolkit</small></div>
          <div className="visual-card visual-card-top"><MessageSquareWarning size={17} /><span>Phishing check</span><b>Ready</b></div>
          <div className="visual-card visual-card-right"><KeyRound size={17} /><span>Password health</span><b>Private</b></div>
          <div className="visual-card visual-card-bottom"><Globe2 size={17} /><span>Website review</span><b>Available</b></div>
        </motion.div>
      </section>

      <section className="landing-value-strip">
        {[
          [ShieldCheck, 'Practical tools', 'Understand everyday risks'],
          [Sparkles, 'Interactive learning', 'Practice in safe scenarios'],
          [LockKeyhole, 'Privacy-conscious', 'Use inputs thoughtfully'],
          [Terminal, 'Clear guidance', 'Know what to do next'],
        ].map(([Icon, title, text]) => <div className="value-item" key={title}><Icon size={19} /><div><b>{title}</b><span>{text}</span></div></div>)}
      </section>

      <section id="services" className="landing-section">
        <div className="landing-section-heading"><div><span className="section-kicker">SECURITY SERVICES</span><h2>Everything you need to build safer digital habits.</h2></div><p>Explore focused tools that turn security questions into understandable next steps.</p></div>
        <div className="service-grid">
          {services.map(({ icon: Icon, ...service }) => <article className="service-card" key={service.title}>
            <div className="service-icon"><Icon size={22} /></div><span className="service-category">{service.category}</span><h3>{service.title}</h3><p>{service.description}</p>
            <ul>{service.points.map(point => <li key={point}><CheckCircle2 size={14} />{point}</li>)}</ul>
            <Link to={service.href} className="service-link">{service.cta} <ArrowRight size={15} /></Link>
          </article>)}
        </div>
      </section>

      <section id="simulations" className="landing-simulation-section">
        <div className="landing-section-heading"><div><span className="section-kicker">SIMULATION LAB</span><h2>Don’t just read about cybersecurity. Experience it.</h2></div><p>Practice recognizing threats and choosing safer actions in a safe virtual environment.</p></div>
        <div className="simulation-showcase">
          <div className="simulation-tabs">{[['phishing', 'Spot the phishing attempt'], ['identity', 'Secure your digital identity'], ['incident', 'Respond to an incident']].map(([id, label], index) => <button key={id} className={activePreview === id ? 'active' : ''} onClick={() => setActivePreview(id)}><span>0{index + 1}</span>{label}</button>)}</div>
          <div className="simulation-preview">
            {activePreview === 'phishing' && <><MessageSquareWarning size={34} /><span className="preview-label">SIMULATED MESSAGE</span><h3>“Your account needs urgent verification”</h3><p>Tap suspicious elements, learn why urgency is a warning sign, and practice slowing down before you click.</p></>}
            {activePreview === 'identity' && <><KeyRound size={34} /><span className="preview-label">SECURITY CHECKLIST</span><h3>Build a stronger digital identity</h3><p>Explore password strength, multifactor authentication, and account recovery choices using fictional data.</p></>}
            {activePreview === 'incident' && <><Shield size={34} /><span className="preview-label">DECISION SCENARIO</span><h3>What would you do next?</h3><p>Choose a safe response to a fictional incident and get immediate educational feedback.</p></>}
            <Link to="/simulation-lab" className="landing-primary-button">Explore the lab <ArrowRight size={17} /></Link>
          </div>
        </div>
      </section>

      <section id="how-it-works" className="landing-section how-section">
        <div className="landing-section-heading centered"><span className="section-kicker">HOW IT WORKS</span><h2>Security guidance without the jargon.</h2></div>
        <div className="steps-grid">{[['01', 'Choose your tool', 'Select a security checker, learning module, or guided scenario.'], ['02', 'Explore and analyze', 'Submit supported input or complete a safe, interactive exercise.'], ['03', 'Learn and improve', 'Understand findings, follow recommendations, and build better habits.']].map(([number, title, text]) => <div className="step-card" key={number}><span>{number}</span><h3>{title}</h3><p>{text}</p></div>)}</div>
      </section>

      <section id="faq" className="landing-faq-section"><div className="landing-section-heading centered"><span className="section-kicker">FAQ</span><h2>Questions, answered clearly.</h2></div><div className="faq-list">{faqs.map(([question, answer], index) => <div className={`faq-item ${openFaq === index ? 'open' : ''}`} key={question}><button onClick={() => setOpenFaq(openFaq === index ? -1 : index)} aria-expanded={openFaq === index}><span>{question}</span><ChevronDown size={18} /></button>{openFaq === index && <p>{answer}</p>}</div>)}</div></section>

      <section className="landing-final-cta"><span className="section-kicker">START WITH ONE SMALL STEP</span><h2>Take the first step toward safer digital living.</h2><p>Explore practical tools, learn to recognize digital threats, and build habits for a more confident online life.</p><div><Link to="/signup" className="landing-primary-button">Create your account <ArrowRight size={17} /></Link><a href="#services" className="landing-secondary-button">Explore security tools</a></div></section>
      <footer className="landing-footer"><div><a href="#home" className="landing-brand"><span className="landing-brand-mark"><ShieldCheck size={19} /></span>Rakshak</a><p>Practical cybersecurity tools and guided learning for everyday digital life.</p></div><div><b>Explore</b><a href="#services">Security services</a><a href="#simulations">Simulation Lab</a><a href="#faq">FAQ</a></div><div><b>Account</b><Link to="/login">Log in</Link><Link to="/signup">Sign up</Link><Link to="/dashboard">Dashboard</Link></div><div><b>Note</b><p>Rakshak provides educational checks and guidance, not a substitute for a professional security audit.</p></div><small>© {new Date().getFullYear()} Rakshak. Learn. Practice. Protect.</small></footer>
    </main>
  );
};

export default LandingPage;
