import { ChevronLeft, ChevronRight } from 'lucide-react'

interface Props {
  page: number
  perPage: number
  totalCount: number
  onPageChange: (page: number) => void
}

export default function Pagination({ page, perPage, totalCount, onPageChange }: Props) {
  const totalPages = Math.max(1, Math.ceil(totalCount / perPage))
  const from = totalCount === 0 ? 0 : (page - 1) * perPage + 1
  const to   = Math.min(page * perPage, totalCount)

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t text-sm"
         style={{ borderColor: 'rgb(var(--border))', color: 'rgb(var(--muted))' }}>
      <span>{totalCount === 0 ? 'No results' : `${from}–${to} of ${totalCount}`}</span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          className="p-1 rounded disabled:opacity-30 hover:bg-[rgb(var(--surface-2))] transition-colors"
          aria-label="Previous page"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        <span className="px-2">
          {page} / {totalPages}
        </span>
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
          className="p-1 rounded disabled:opacity-30 hover:bg-[rgb(var(--surface-2))] transition-colors"
          aria-label="Next page"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}
