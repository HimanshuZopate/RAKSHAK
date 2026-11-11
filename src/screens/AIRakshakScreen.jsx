import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ArrowLeft, Bot, Send, SquarePen, Copy, Check, X, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';

// One chat request may fail over across several AI providers on the backend
// (bounded server-side to ~30s), so it needs more than the default 10s timeout.
const CHAT_TIMEOUT_MS = 45000;
const MAX_QUESTION_CHARS = 2000;
const HISTORY_LIMIT = 8; // most recent turns sent as context
const HISTORY_ITEM_CHARS = 3000; // backend also caps each item at 3000
const HISTORY_CHAR_BUDGET = 20000; // keeps the request well under the API body limit
const NEAR_BOTTOM_PX = 120;

const SUGGESTIONS = [
  'How can I tell if an email or SMS is a scam?',
  'I clicked a suspicious link. What should I do now?',
  'How do I create a strong password and turn on 2FA?',
  'What is SQL injection and how is it prevented?',
];

let messageSeq = 0;
const newId = () => `m${Date.now().toString(36)}${(messageSeq += 1)}`;

// ── Lightweight, safe Markdown renderer ─────────────────────────────────────
// Renders the subset of Markdown that AI answers use. Everything is rendered as
// React elements (no innerHTML), and links are restricted to http(s)/mailto.

const safeHref = (url) => {
  const value = String(url || '').trim();
  return /^(https?:\/\/|mailto:)/i.test(value) ? value : null;
};

// Groups: 1 code, 2 link, 3 bold, 4 italic, 5 bare URL. Underscore emphasis is
// intentionally unsupported (it collides with snake_case identifiers), and no
// regex lookbehind is used so older Safari versions can parse the bundle.
const INLINE_PATTERN =
  /(`[^`\n]+`)|(\[[^\]\n]+\]\([^)\s]+\))|(\*\*[^*\n]+?\*\*)|(\*[^*\s][^*\n]*?\*)|(https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g;

const renderInline = (text, keyPrefix = 'i') => {
  if (!text) return null;
  const nodes = [];
  let lastIndex = 0;
  let match;
  const pattern = new RegExp(INLINE_PATTERN.source, 'g');

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) nodes.push(text.slice(lastIndex, match.index));
    const token = match[0];
    const key = `${keyPrefix}-${match.index}`;

    if (match[1]) {
      nodes.push(<code key={key} className="ai-md-code">{token.slice(1, -1)}</code>);
    } else if (match[2]) {
      const split = token.indexOf('](');
      const label = token.slice(1, split);
      const href = safeHref(token.slice(split + 2, -1));
      nodes.push(
        href ? (
          <a key={key} href={href} target="_blank" rel="noopener noreferrer">{renderInline(label, key)}</a>
        ) : (
          <span key={key}>{renderInline(label, key)}</span>
        )
      );
    } else if (match[3]) {
      nodes.push(<strong key={key}>{renderInline(token.slice(2, -2), key)}</strong>);
    } else if (match[4]) {
      nodes.push(<em key={key}>{renderInline(token.slice(1, -1), key)}</em>);
    } else if (match[5]) {
      nodes.push(<a key={key} href={token} target="_blank" rel="noopener noreferrer">{token}</a>);
    }
    lastIndex = pattern.lastIndex;
  }
  if (lastIndex < text.length) nodes.push(text.slice(lastIndex));
  return nodes;
};

const splitTableRow = (line) =>
  line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((cell) => cell.trim());

const isTableSeparator = (line) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line);
const isListLine = (line) => /^\s*([-*+•]|\d+[.)])\s+/.test(line);
const isOrderedLine = (line) => /^\s*\d+[.)]\s+/.test(line);
const isBlockStart = (line) =>
  /^\s*(```|#{1,6}\s|>|(-{3,}|\*{3,}|_{3,})\s*$)/.test(line) || isListLine(line) || /^\s*\|.*\|\s*$/.test(line);

export const MarkdownMessage = ({ content }) => {
  const lines = String(content || '').replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    const key = `b${blocks.length}`;

    if (!trimmed) {
      i += 1;
      continue;
    }

    // Fenced code block (an unterminated fence runs to the end of the message)
    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim();
      const code = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        code.push(lines[i]);
        i += 1;
      }
      i += 1; // closing fence
      blocks.push(
        <div key={key} className="ai-md-codeblock">
          {lang && <span className="ai-md-codelang">{lang}</span>}
          <pre><code>{code.join('\n')}</code></pre>
        </div>
      );
      continue;
    }

    // Horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      blocks.push(<hr key={key} className="ai-md-hr" />);
      i += 1;
      continue;
    }

    // Heading (rendered compactly; chat answers rarely need large headings)
    const heading = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      const Tag = heading[1].length <= 2 ? 'h3' : 'h4';
      blocks.push(
        <Tag key={key} className={`ai-md-${Tag}`}>
          {renderInline(heading[2].replace(/\s*#+\s*$/, ''), key)}
        </Tag>
      );
      i += 1;
      continue;
    }

    // Table: header row followed by a separator row
    if (trimmed.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const header = splitTableRow(trimmed);
      const rows = [];
      i += 2;
      while (i < lines.length && lines[i].trim() && lines[i].includes('|')) {
        rows.push(splitTableRow(lines[i]));
        i += 1;
      }
      blocks.push(
        <div key={key} className="ai-md-table-wrap">
          <table className="ai-md-table">
            <thead>
              <tr>{header.map((cell, c) => <th key={c}>{renderInline(cell, `${key}h${c}`)}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((row, r) => (
                <tr key={r}>
                  {header.map((_, c) => <td key={c}>{renderInline(row[c] || '', `${key}r${r}c${c}`)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    // Blockquote (consecutive "> " lines)
    if (trimmed.startsWith('>')) {
      const quote = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quote.push(lines[i].trim().replace(/^>\s?/, ''));
        i += 1;
      }
      blocks.push(
        <blockquote key={key} className="ai-md-quote">
          {quote.filter(Boolean).map((q, n) => <p key={n}>{renderInline(q, `${key}-${n}`)}</p>)}
        </blockquote>
      );
      continue;
    }

    // Lists: items may be separated by blank lines and keep their numbering.
    if (isListLine(line)) {
      const ordered = isOrderedLine(line);
      const start = ordered ? parseInt(trimmed, 10) : undefined;
      const items = [];
      while (i < lines.length) {
        const current = lines[i];
        if (!current.trim()) {
          // A blank line ends the list unless another item of the same kind follows.
          let next = i + 1;
          while (next < lines.length && !lines[next].trim()) next += 1;
          if (next < lines.length && isListLine(lines[next]) && isOrderedLine(lines[next]) === ordered) {
            i = next;
            continue;
          }
          break;
        }
        const item = current.match(/^(\s*)([-*+•]|\d+[.)])\s+(.*)$/);
        if (item) {
          const nested = item[1].length >= 2;
          if (!nested && /\d/.test(item[2]) !== ordered) break; // switches list type
          items.push({ text: item[3], nested });
        } else if (items.length && !isBlockStart(current)) {
          items[items.length - 1].text += ` ${current.trim()}`; // wrapped continuation line
        } else {
          break;
        }
        i += 1;
      }
      const ListTag = ordered ? 'ol' : 'ul';
      blocks.push(
        <ListTag key={key} className="ai-md-list" start={ordered && start > 1 ? start : undefined}>
          {items.map((item, n) => (
            <li key={n} className={item.nested ? 'ai-md-nested' : undefined}>
              {renderInline(item.text, `${key}-${n}`)}
            </li>
          ))}
        </ListTag>
      );
      continue;
    }

    // Paragraph: consecutive plain lines until a blank line or another block
    const paragraph = [trimmed];
    i += 1;
    while (i < lines.length && lines[i].trim() && !isBlockStart(lines[i])) {
      paragraph.push(lines[i].trim());
      i += 1;
    }
    blocks.push(
      <p key={key} className="ai-md-p">
        {paragraph.map((text, n) => (
          <React.Fragment key={n}>
            {n > 0 && <br />}
            {renderInline(text, `${key}-${n}`)}
          </React.Fragment>
        ))}
      </p>
    );
  }

  return <div className="ai-md">{blocks}</div>;
};

// ── Error messages (user-facing; no internal codes or infrastructure details) ─
const describeError = (requestError) => {
  if (requestError?.code === 'ECONNABORTED') {
    return 'AI RAKSHAK is taking longer than usual to respond. Please try again.';
  }
  if (!requestError?.response) return 'Unable to connect right now. Please check your connection and try again.';
  const status = requestError.response.status;
  const code = requestError.response.data?.code;
  if (status === 401) return 'Your session has expired. Please sign in again to continue.';
  if (status === 429) return 'You are sending messages too quickly. Please wait a moment and try again.';
  if (code === 'INVALID_QUESTION') return `Please enter a question of up to ${MAX_QUESTION_CHARS} characters.`;
  if (status === 413 || code === 'PAYLOAD_TOO_LARGE') return 'This conversation has become too long. Start a new chat to continue.';
  if (status === 400 || status === 403) return 'That message could not be sent. Please rephrase it and try again.';
  return 'AI RAKSHAK is temporarily unavailable. Please try again in a moment.';
};

/** Most recent turns that fit the context budget, oldest first. */
const buildHistory = (messages) => {
  const history = [];
  let budget = HISTORY_CHAR_BUDGET;
  for (let n = messages.length - 1; n >= 0 && history.length < HISTORY_LIMIT; n -= 1) {
    const content = messages[n].content.slice(0, HISTORY_ITEM_CHARS);
    if (content.length > budget) break;
    budget -= content.length;
    history.unshift({ role: messages[n].role, content });
  }
  return history;
};

const AIRakshakScreen = () => {
  const navigate = useNavigate();
  const [messages, setMessages] = useState([]);
  const [question, setQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copiedId, setCopiedId] = useState(null);

  const messagesRef = useRef(null);
  const textareaRef = useRef(null);
  const inFlightRef = useRef(false); // synchronous guard against double submission
  const abortRef = useRef(null);
  const conversationRef = useRef(0); // bumps on "new chat"; stale replies are discarded
  const stickToBottomRef = useRef(true);
  const copyTimerRef = useRef(null);

  // Abort any pending request and timers when leaving the page.
  useEffect(
    () => () => {
      abortRef.current?.abort();
      clearTimeout(copyTimerRef.current);
    },
    []
  );

  // Follow new messages only while the user is at (or near) the bottom, so
  // reading earlier messages is not interrupted.
  useLayoutEffect(() => {
    const pane = messagesRef.current;
    if (pane && stickToBottomRef.current) pane.scrollTop = pane.scrollHeight;
  }, [messages, loading]);

  const handleScroll = () => {
    const pane = messagesRef.current;
    if (!pane) return;
    stickToBottomRef.current = pane.scrollHeight - pane.scrollTop - pane.clientHeight < NEAR_BOTTOM_PX;
  };

  // Auto-grow the input up to its CSS max-height.
  useLayoutEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
  }, [question]);

  const send = useCallback(
    async (text) => {
      const query = String(text ?? '').trim();
      if (!query || inFlightRef.current) return;
      if (query.length > MAX_QUESTION_CHARS) {
        setError(`Please keep your question under ${MAX_QUESTION_CHARS} characters.`);
        return;
      }

      inFlightRef.current = true;
      const conversation = conversationRef.current;
      const controller = new AbortController();
      abortRef.current = controller;

      const history = buildHistory(messages);
      const userMessage = { id: newId(), role: 'user', content: query };

      setError('');
      setQuestion('');
      stickToBottomRef.current = true;
      setMessages((current) => [...current, userMessage]);
      setLoading(true);

      try {
        const response = await api.post(
          '/ai/chat',
          { question: query, history },
          { timeout: CHAT_TIMEOUT_MS, signal: controller.signal }
        );
        if (conversation !== conversationRef.current) return; // chat was cleared meanwhile
        const answer = typeof response.data?.answer === 'string' ? response.data.answer.trim() : '';
        if (!answer) throw new Error('EMPTY_ANSWER');
        setMessages((current) => [...current, { id: newId(), role: 'assistant', content: answer }]);
      } catch (requestError) {
        if (controller.signal.aborted || conversation !== conversationRef.current) return;
        setError(
          requestError?.message === 'EMPTY_ANSWER'
            ? 'AI RAKSHAK could not generate an answer. Please try again.'
            : describeError(requestError)
        );
        // Remove the unanswered message and give the text back, so retrying
        // does not create a duplicate entry. Never overwrite newly typed text.
        setMessages((current) => current.filter((m) => m.id !== userMessage.id));
        setQuestion((current) => current || query);
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
        if (conversation === conversationRef.current) {
          inFlightRef.current = false;
          setLoading(false);
          textareaRef.current?.focus();
        }
      }
    },
    [messages]
  );

  const handleSubmit = (event) => {
    event.preventDefault();
    send(question);
  };

  const handleKeyDown = (event) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      send(question);
    }
  };

  const startNewChat = () => {
    conversationRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    inFlightRef.current = false;
    setLoading(false);
    setMessages([]);
    setError('');
    stickToBottomRef.current = true;
    textareaRef.current?.focus();
  };

  const copyMessage = async (message) => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopiedId(message.id);
      clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // Clipboard unavailable (insecure context or permission denied); nothing to do.
    }
  };

  const isEmpty = messages.length === 0;
  const nearLimit = question.length > MAX_QUESTION_CHARS - 200;

  return (
    <main className="ai-page">
      <div className="ai-grid" aria-hidden="true" />

      <section className="ai-panel" aria-label="AI RAKSHAK chat">
        <header className="ai-header">
          <button
            type="button"
            className="ai-icon-btn"
            onClick={() => navigate('/dashboard')}
            aria-label="Back to dashboard"
            title="Back to dashboard"
          >
            <ArrowLeft size={18} />
          </button>

          <div className="ai-title">
            <span className="ai-avatar" aria-hidden="true">
              <ShieldCheck size={20} />
            </span>
            <div>
              <h1>AI RAKSHAK</h1>
              <p>Cybersecurity assistant</p>
            </div>
          </div>

          {!isEmpty && (
            <button type="button" className="ai-icon-btn" onClick={startNewChat} aria-label="Start a new chat" title="New chat">
              <SquarePen size={17} />
            </button>
          )}
        </header>

        <div
          ref={messagesRef}
          className="ai-messages"
          onScroll={handleScroll}
          role="log"
          aria-live="polite"
          aria-relevant="additions"
        >
          {isEmpty ? (
            <div className="ai-empty">
              <span className="ai-empty-icon" aria-hidden="true">
                <Bot size={28} />
              </span>
              <h2>How can I help you stay safe online?</h2>
              <p>Ask about scams, passwords, website security, malware or what to do after an incident.</p>
              <div className="ai-suggestions">
                {SUGGESTIONS.map((text) => (
                  <button type="button" key={text} onClick={() => send(text)} disabled={loading}>
                    {text}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((message) => (
              <article key={message.id} className={`ai-message ${message.role}`}>
                {message.role === 'assistant' ? (
                  <>
                    <span className="ai-message-avatar" aria-hidden="true">
                      <ShieldCheck size={15} />
                    </span>
                    <div className="ai-bubble">
                      <MarkdownMessage content={message.content} />
                      <button
                        type="button"
                        className="ai-copy-btn"
                        onClick={() => copyMessage(message)}
                        aria-label={copiedId === message.id ? 'Copied' : 'Copy answer'}
                        title={copiedId === message.id ? 'Copied' : 'Copy'}
                      >
                        {copiedId === message.id ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="ai-bubble">{message.content}</div>
                )}
              </article>
            ))
          )}

          {loading && (
            <article className="ai-message assistant" aria-label="AI RAKSHAK is typing">
              <span className="ai-message-avatar" aria-hidden="true">
                <ShieldCheck size={15} />
              </span>
              <div className="ai-bubble ai-typing">
                <span />
                <span />
                <span />
              </div>
            </article>
          )}
        </div>

        {error && (
          <div className="ai-error" role="alert">
            <span>{error}</span>
            <button type="button" onClick={() => setError('')} aria-label="Dismiss message">
              <X size={14} />
            </button>
          </div>
        )}

        <form className="ai-composer" onSubmit={handleSubmit}>
          <textarea
            ref={textareaRef}
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask a cybersecurity question…"
            maxLength={MAX_QUESTION_CHARS}
            rows={1}
            aria-label="Message AI RAKSHAK"
          />
          <button type="submit" disabled={loading || !question.trim()} aria-label="Send message" title="Send">
            <Send size={18} />
          </button>
        </form>
        <p className="ai-footnote">
          {nearLimit ? (
            `${question.length}/${MAX_QUESTION_CHARS} characters`
          ) : (
            <>
              Never share passwords, OTPs or PINs in chat.
              <span className="ai-footnote-hint"> Shift + Enter adds a new line.</span>
            </>
          )}
        </p>
      </section>
    </main>
  );
};

export default AIRakshakScreen;
