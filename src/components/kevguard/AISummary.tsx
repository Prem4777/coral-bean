type Props = {
  text?: string | null;
};

export function AISummary({ text }: Props) {
  return (
    <p className="text-[16px] leading-relaxed text-white/70">
      {text || "No AI summary available yet. Run a repository analysis to generate one."}
    </p>
  );
}
