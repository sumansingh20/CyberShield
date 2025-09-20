"use client";

import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { Shield, Image, Video, Music, FileText } from "lucide-react";

export default function DeepfakeIdentificationPage() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    // Simulate AI detection (replace with real API call)
    setTimeout(() => {
      setResult("This content appears to be AI-generated.");
      setLoading(false);
    }, 1500);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <Card className="w-full max-w-xl shadow-2xl">
        <CardHeader className="text-center pb-2">
          <div className="mx-auto mb-4 w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Deepfake & AI Content Identification
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Detect AI-generated images, videos, music, or text
          </p>
        </CardHeader>
        <CardContent className="space-y-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              type="text"
              placeholder="Paste image/video/music/text URL or content here..."
              value={input}
              onChange={e => setInput(e.target.value)}
              required
            />
            <Button type="submit" className="w-full bg-blue-600 hover:bg-blue-700" disabled={loading}>
              {loading ? "Analyzing..." : "Detect Deepfake / AI Content"}
            </Button>
          </form>
          {result && (
            <div className="p-4 rounded-xl bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200/50 dark:border-blue-800/50 text-center">
              <span className="font-semibold text-blue-700 dark:text-blue-300">{result}</span>
            </div>
          )}
          <div className="flex justify-center gap-6 pt-4">
            <Image className="w-8 h-8 text-blue-400" />
            <Video className="w-8 h-8 text-indigo-400" />
            <Music className="w-8 h-8 text-purple-400" />
            <FileText className="w-8 h-8 text-green-400" />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
