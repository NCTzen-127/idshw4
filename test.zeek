event http_reply(c: connection, version : string, code : count, reason : string)
{
	SumStats::observe("total responce", [$host = c$id$orig_h], [$num = 1]); 	
	if (code == 404) 
	{ 
		SumStats::observe("404responce", [$host = c$id$orig_h], [$num = 1]); 		
		SumStats::observe("404responce of unique url", [$host = c$id$orig_h], [$str = c$http$uri]);
	}	
}
event zeek_init()
{
	local r1 = SumStats::Reducer($stream = "total responce", $apply = set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream = "404responce", $apply = set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream = "404responce of unique url", $apply = set(SumStats::UNIQUE));
	SumStats::create([$name = "scanning detection", 
		$epoch = 10min, $reducers = set(r1, r2, r3),
		$epoch_result(ts:time, key : SumStats::Key, result : SumStats::Result) =
		{
			local ratio1 : double = result["404responce"]$sum / result["total responce"]$sum;
	        local ratio2 : double = result["404responce of unique url"]$unique / result["404responce"]$sum;
			if (result["404responce"]$sum > 2 && ratio1 > 0.2 && ratio2 > 0.5) 
			{
				print fmt("%s is a scanner with %.0f scan attemps on %.0f urls",
					key$host, result["404responce"]$sum, result["404responce of unique url"]$sum);
			}
		}]);
}
