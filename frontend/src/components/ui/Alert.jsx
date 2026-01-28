/**
 * Reusable Alert component for errors and success messages
 */

export function Alert({ type = 'error', message, onClose }) {
  if (!message) return null;

  const styles = {
    error: {
      bg: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800',
      text: 'text-red-600 dark:text-red-400'
    },
    success: {
      bg: 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800',
      text: 'text-green-600 dark:text-green-400'
    },
    info: {
      bg: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800',
      text: 'text-blue-600 dark:text-blue-400'
    },
    warning: {
      bg: 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800',
      text: 'text-orange-600 dark:text-orange-400'
    }
  };

  const { bg, text } = styles[type];

  return (
    <div className={`p-4 border rounded-lg ${bg} flex items-center justify-between`}>
      <p className={`text-sm ${text} flex-1`}>{message}</p>
      {onClose && (
        <button
          onClick={onClose}
          className={`ml-4 ${text} hover:opacity-70 transition-opacity`}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </div>
  );
}
