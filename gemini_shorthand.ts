import { GoogleGenAI } from "@google/genai";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

export const shorthandSchema = z.object({
  shorthand: z
    .string()
    .min(2)
    .max(48)
    .describe(
      "Terse filesystem-safe nickname for a podcast feed or episode. Prefer dash/underscore separators; avoid spaces."
    ),
});

export type GeminiShorthandArgs = {
  kind: string;
  title: string;
  detail?: string;
  log?: (...args: unknown[]) => void;
};

const getApiKey = () => Bun.env.GEMINI_API_KEY || Bun.env.GOOGLE_API_KEY || "";
const getModel = () => Bun.env.GEMINI_MODEL || "gemini-2.5-flash";

export const parseShorthandText = (text: string): string => {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Empty Gemini shorthand response");

  let parsed: unknown = trimmed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Keep raw text fallback if it is not JSON.
  }

  if (typeof parsed === "string") {
    return shorthandSchema.shape.shorthand.parse(parsed).trim();
  }

  if (parsed && typeof parsed === "object") {
    const candidate =
      (parsed as Record<string, unknown>).shorthand ??
      (parsed as Record<string, unknown>).short;
    if (typeof candidate === "string") {
      return shorthandSchema.shape.shorthand.parse(candidate).trim();
    }
  }

  throw new Error("Unexpected Gemini shorthand payload shape");
};

export async function generateGeminiShorthand(
  args: GeminiShorthandArgs
): Promise<string | null> {
  const { kind, title, detail, log } = args;
  const logger = log ?? (() => {});
  const apiKey = getApiKey();
  if (!apiKey) {
    logger("Gemini shorthand skipped: missing API key");
    return null;
  }

  const ai = new GoogleGenAI({ apiKey });
  const model = getModel();
  const promptLines = [
    `Create a terse filesystem-safe nickname for a ${kind}.`,
    "Goal: about 15-30 characters, human-style shorthand.",
    "Acceptable separators: dash or underscore; no spaces otherwise.",
    "Do NOT repeat the title verbatim; compress or abbreviate it instead.",
    "Drop filler like podcast, episode, official, the.",
    "Prefer 3-5 words, shorten long ones if needed but keep it readable.",
    `Title: ${title}`,
  ];
  if (detail) promptLines.push(`Context: ${detail}`);

  logger("Gemini shorthand request", { kind, model, title });

  try {
    const response = await ai.models.generateContent({
      model,
      contents: promptLines.join("\n"),
      config: {
        responseMimeType: "application/json",
        responseJsonSchema: zodToJsonSchema(shorthandSchema),
      },
    });

    const shorthand = parseShorthandText(response.text);
    if (!shorthand) {
      logger("Gemini shorthand empty after parsing");
      return null;
    }
    logger("Gemini shorthand success", { shorthand });
    return shorthand;
  } catch (err) {
    logger("Gemini shorthand failed", err);
    return null;
  }
}
