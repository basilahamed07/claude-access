import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { get, type Page } from "./client";

type Query = Record<string, string | number | boolean | null | undefined>;

/** Keyset-paginated list: `next_cursor` drives "Load more". */
export function useList<T>(key: readonly unknown[], path: string, query: Query = {}, opts: { refetchInterval?: number; enabled?: boolean } = {}) {
  const q = useInfiniteQuery({
    queryKey: [...key, path, query],
    initialPageParam: "" as string,
    queryFn: ({ pageParam }) => get<Page<T>>(path, { limit: 50, ...query, cursor: pageParam || undefined }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: opts.refetchInterval,
    enabled: opts.enabled,
  });
  return {
    ...q,
    rows: q.data?.pages.flatMap((p) => p.items),
    loadMore: () => void q.fetchNextPage(),
  };
}

export function useOne<T>(key: readonly unknown[], path: string, query?: Query, opts: { refetchInterval?: number; enabled?: boolean } = {}) {
  return useQuery({ queryKey: [...key, path, query], queryFn: () => get<T>(path, query), refetchInterval: opts.refetchInterval, enabled: opts.enabled });
}
