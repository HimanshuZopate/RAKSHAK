import { askExternalLLM, getAIStatus, ChatMessage } from './aiProviderService';

export { getAIStatus };

export const askGroq = async (messageOrMessages: any): Promise<string> => {
  let messages: ChatMessage[] = [];

  if (Array.isArray(messageOrMessages)) {
    messages = messageOrMessages;
  } else if (messageOrMessages && typeof messageOrMessages === 'object') {
    messages = [messageOrMessages];
  } else if (typeof messageOrMessages === 'string') {
    messages = [{ role: 'user', content: messageOrMessages }];
  }

  const result = await askExternalLLM(messages);
  return result.answer;
};
