import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AIRakshakScreen, { MarkdownMessage } from './AIRakshakScreen';
import api from '../utils/api';

jest.mock('../utils/api', () => ({ __esModule: true, default: { post: jest.fn(), get: jest.fn() } }));

// jsdom does not implement layout scrolling APIs used by the chat.
beforeAll(() => {
  Element.prototype.scrollTo = jest.fn();
});

const renderChat = () =>
  render(
    <MemoryRouter>
      <AIRakshakScreen />
    </MemoryRouter>
  );

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

describe('MarkdownMessage', () => {
  test('renders headings, rules, tables and code without raw Markdown syntax', () => {
    const { container } = render(
      <MarkdownMessage
        content={[
          '# Title',
          '---',
          '| Step | Action |',
          '|------|--------|',
          '| 1 | Call **1930** |',
          '',
          '```js',
          'const x = 1;',
          '```',
          'Some *emphasis* and `code`.',
        ].join('\n')}
      />
    );
    expect(container.querySelector('h3').textContent).toBe('Title');
    expect(container.querySelector('hr')).not.toBeNull();
    expect(container.querySelectorAll('td')).toHaveLength(2);
    expect(container.querySelector('td strong').textContent).toBe('1930');
    expect(container.querySelector('pre code').textContent).toBe('const x = 1;');
    expect(container.querySelector('em').textContent).toBe('emphasis');
    expect(container.textContent).not.toMatch(/[#|*`]|---/);
  });

  test('keeps ordered list numbering across blank lines', () => {
    const { container } = render(<MarkdownMessage content={'1. First\n\n2. Second\n\n3. Third'} />);
    const lists = container.querySelectorAll('ol');
    expect(lists).toHaveLength(1);
    expect(lists[0].querySelectorAll('li')).toHaveLength(3);
  });

  test('only renders safe links', () => {
    const { container } = render(
      <MarkdownMessage content={'[ok](https://cybercrime.gov.in) and [bad](javascript:alert(1))'} />
    );
    const links = container.querySelectorAll('a');
    expect(links).toHaveLength(1);
    expect(links[0].getAttribute('href')).toBe('https://cybercrime.gov.in');
    expect(links[0].getAttribute('rel')).toContain('noopener');
    expect(container.textContent).toContain('bad');
  });

  test('handles an empty or unterminated code fence without swallowing the message', () => {
    const { container } = render(<MarkdownMessage content={'```\n```\nAfter the fence'} />);
    expect(container.textContent).toContain('After the fence');
  });
});

describe('AIRakshakScreen chat lifecycle', () => {
  beforeEach(() => {
    api.post.mockReset();
  });

  test('shows a minimal empty state without provider or system details', () => {
    renderChat();
    expect(screen.getByText('How can I help you stay safe online?')).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/gemini|groq|openai|provider|engine|api key|quota/i);
  });

  test('rapid Enter presses send exactly one request; reply appears once', async () => {
    const pending = deferred();
    api.post.mockReturnValue(pending.promise);
    renderChat();

    const input = screen.getByLabelText('Message AI RAKSHAK');
    fireEvent.change(input, { target: { value: 'What is phishing?' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    fireEvent.keyDown(input, { key: 'Enter' });
    fireEvent.click(screen.getByLabelText('Send message'));

    expect(api.post).toHaveBeenCalledTimes(1);
    expect(input.value).toBe('');
    expect(screen.getByLabelText('AI RAKSHAK is typing')).toBeInTheDocument();

    await act(async () => {
      pending.resolve({ data: { success: true, answer: 'Phishing is a scam.', provider: 'gemini' } });
    });

    expect(await screen.findByText('Phishing is a scam.')).toBeInTheDocument();
    expect(screen.getAllByText('What is phishing?')).toHaveLength(1);
    expect(screen.queryByLabelText('AI RAKSHAK is typing')).toBeNull();
    expect(document.body.textContent).not.toMatch(/gemini/i);
  });

  test('sends earlier turns as history and the current question separately', async () => {
    api.post
      .mockResolvedValueOnce({ data: { answer: 'First answer' } })
      .mockResolvedValueOnce({ data: { answer: 'Second answer' } });
    renderChat();
    const input = screen.getByLabelText('Message AI RAKSHAK');

    fireEvent.change(input, { target: { value: 'Q1' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    await screen.findByText('First answer');

    fireEvent.change(input, { target: { value: 'Q2' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    await screen.findByText('Second answer');

    const [, body] = api.post.mock.calls[1];
    expect(body.question).toBe('Q2');
    expect(body.history).toEqual([
      { role: 'user', content: 'Q1' },
      { role: 'assistant', content: 'First answer' },
    ]);
  });

  test('Shift+Enter does not send', () => {
    renderChat();
    const input = screen.getByLabelText('Message AI RAKSHAK');
    fireEvent.change(input, { target: { value: 'line one' } });
    fireEvent.keyDown(input, { key: 'Enter', shiftKey: true });
    expect(api.post).not.toHaveBeenCalled();
  });

  test('on failure shows a friendly error, removes the unanswered message and restores the input', async () => {
    api.post.mockRejectedValueOnce({ response: { status: 503, data: { code: 'AI_CHAT_UNAVAILABLE', error: 'internal detail' } } });
    renderChat();
    const input = screen.getByLabelText('Message AI RAKSHAK');
    fireEvent.change(input, { target: { value: 'Is this link safe?' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily unavailable');
    expect(screen.queryByText('internal detail')).toBeNull();
    expect(screen.queryByText('Is this link safe?', { selector: '.ai-bubble' })).toBeNull();
    expect(input.value).toBe('Is this link safe?');
    expect(screen.getByLabelText('Send message')).not.toBeDisabled();
  });

  test('starting a new chat discards a reply that arrives afterwards', async () => {
    const pending = deferred();
    api.post.mockReturnValue(pending.promise);
    renderChat();
    const input = screen.getByLabelText('Message AI RAKSHAK');
    fireEvent.change(input, { target: { value: 'Old question' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    fireEvent.click(screen.getByLabelText('Start a new chat'));
    await act(async () => {
      pending.resolve({ data: { answer: 'Late answer' } });
    });

    await waitFor(() => expect(screen.getByText('How can I help you stay safe online?')).toBeInTheDocument());
    expect(screen.queryByText('Late answer')).toBeNull();
    expect(screen.queryByText('Old question')).toBeNull();
  });

  test('suggestion chips send their question', async () => {
    api.post.mockResolvedValueOnce({ data: { answer: 'Here is how.' } });
    renderChat();
    fireEvent.click(screen.getByText('How do I create a strong password and turn on 2FA?'));
    expect(api.post).toHaveBeenCalledWith(
      '/ai/chat',
      expect.objectContaining({ question: 'How do I create a strong password and turn on 2FA?', history: [] }),
      expect.objectContaining({ timeout: 45000 })
    );
    expect(await screen.findByText('Here is how.')).toBeInTheDocument();
  });
});
