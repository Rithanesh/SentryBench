import { Link } from "react-router-dom";
import type { LucideIcon } from "lucide-react";

export default function EmptyState({
  icon: Icon,
  title,
  description,
  actionLabel,
  actionTo,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  actionTo?: string;
}) {
  return (
    <div className="h-full flex items-center justify-center p-10">
      <div className="text-center max-w-sm">
        <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-4">
          <Icon size={20} className="text-slate-500" />
        </div>
        <div className="text-sm font-medium text-slate-200 mb-1">{title}</div>
        <p className="text-sm text-slate-500 mb-4">{description}</p>
        {actionLabel && actionTo && (
          <Link
            to={actionTo}
            className="inline-block bg-indigo-500 hover:bg-indigo-400 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
          >
            {actionLabel}
          </Link>
        )}
      </div>
    </div>
  );
}
