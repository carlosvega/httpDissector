import java.util.Comparator;
import java.util.Map;

public class CounterComparator<X> implements Comparator<Map.Entry<X, Integer>> {
	@Override
	public int compare(Map.Entry<X, Integer> x, Map.Entry<X, Integer> y) {
		if (x.getValue() < y.getValue()) {
			return 1;
		}

		if (x.getValue() > y.getValue()) {
			return -1;
		}

		return 0;

	}
}
