import { test, expect } from "bun:test";
import { GoogleGenAI } from "@google/genai";
import { zodToJsonSchema } from "zod-to-json-schema";
import { parseShorthandText, shorthandSchema } from "./gemini_shorthand";

const apiKey = Bun.env.GEMINI_API_KEY || Bun.env.GOOGLE_API_KEY;
const model = Bun.env.GEMINI_MODEL || "gemini-2.5-flash";

// Integration test: hits the real Gemini API. Skips when no API key is configured.
const integrationTest = apiKey ? test : test.skip;

integrationTest("Gemini returns shorthand as a JSON string payload", async () => {
  const ai = new GoogleGenAI({ apiKey: apiKey! });
  const promptLines = [
    "Create a terse filesystem-safe nickname for a podcast episode.",
    "Goal: about 8-24 characters, human-style shorthand.",
    "Acceptable separators: dash or underscore; no spaces otherwise.",
    "Do NOT repeat the title verbatim; compress or abbreviate it instead.",
    "Drop filler like podcast, episode, official, the.",
    "Prefer 2-4 tokens; blend words if it keeps things short.",
    "Title: Keeping Up With The Fast and Furious Web",
  ];

  const response = await ai.models.generateContent({
    model,
    contents: promptLines.join("\n"),
    config: {
      responseMimeType: "application/json",
      responseJsonSchema: zodToJsonSchema(shorthandSchema),
    },
  });

  const raw = response.text.trim();
  expect(raw.length).toBeGreaterThan(0);

  // Current API behavior: the JSON string represents the shorthand directly, not an object.
  const parsed = JSON.parse(raw);
  expect(typeof parsed).toBe("string");

  const shorthand = parseShorthandText(raw);
  expect(typeof shorthand).toBe("string");
  expect(shorthand.length).toBeGreaterThan(0);
}, 20_000);
