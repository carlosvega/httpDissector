import java.util.Comparator;
import java.util.Map;

public class CounterComparatorByKey<X extends Comparable<X>> implements
		Comparator<Map.Entry<X, Integer>> {
	@Override
	public int compare(Map.Entry<X, Integer> x, Map.Entry<X, Integer> y) {

		return x.getKey().compareTo(y.getKey());

	}

}
