export type TradeSide = "buy" | "sell";

export type PlaceTradeArgs = {
  symbol: string;
  side: TradeSide;
  quantity: number;
  limit: number;
};

export type PlaceTradeResult = {
  success: true;
  tradeId: string;
  executedAt: string;
};

export type TradeRecord = PlaceTradeArgs & {
  tradeId: string;
  executedAt: string;
};
