package backend

import "testing"

func FuzzBucketLoggingConfigEqual(f *testing.F) {
	f.Add("target-bucket", "logs/", "Standard", 300, "target-bucket", "logs/", "Standard", 300)
	f.Add("bucket-a", "prefix/", "Journal", 600, "bucket-a", "prefix/", "Journal", 600)
	f.Add("bucket-a", "prefix/", "", 0, "bucket-a", "prefix/", "Standard", 300)
	f.Add("bucket-a", "logs/", "Standard", 300, "bucket-b", "logs/", "Standard", 300)
	f.Add("", "", "", 0, "", "", "", 0)

	f.Fuzz(
		func(t *testing.T, aBucket, aPrefix, aType string, aRoll int, bBucket, bPrefix, bType string, bRoll int) {
			a := &BucketLoggingStatus{
				LoggingEnabled: &LoggingEnabled{
					TargetBucket:   aBucket,
					TargetPrefix:   aPrefix,
					LoggingType:    aType,
					ObjectRollTime: aRoll,
				},
			}
			b := &BucketLoggingStatus{
				LoggingEnabled: &LoggingEnabled{
					TargetBucket:   bBucket,
					TargetPrefix:   bPrefix,
					LoggingType:    bType,
					ObjectRollTime: bRoll,
				},
			}
			_ = bucketLoggingConfigEqual(a, b)
		},
	)
}

func FuzzBucketLoggingFilterEqual(f *testing.F) {
	f.Add("prefix", "logs/", "prefix", "logs/")
	f.Add("suffix", ".log", "suffix", ".log")
	f.Add("prefix", "a/", "prefix", "b/")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, aName, aValue, bName, bValue string) {
		var a, b *LoggingFilter
		if aName != "" {
			a = &LoggingFilter{
				Key: &LoggingKeyFilter{
					FilterRules: []FilterRule{{Name: aName, Value: aValue}},
				},
			}
		}
		if bName != "" {
			b = &LoggingFilter{
				Key: &LoggingKeyFilter{
					FilterRules: []FilterRule{{Name: bName, Value: bValue}},
				},
			}
		}
		_ = bucketLoggingFilterEqual(a, b)
	})
}

func FuzzBucketLogKeyFormatEqual(f *testing.F) {
	f.Add(true, false, "", true, false, "")
	f.Add(false, true, "DeliveryTime", false, true, "DeliveryTime")
	f.Add(false, true, "EventTime", false, true, "DeliveryTime")
	f.Add(true, false, "", false, true, "EventTime")

	f.Fuzz(
		func(t *testing.T, aSimple, aPartitioned bool, aSource string, bSimple, bPartitioned bool, bSource string) {
			var a, b *TargetObjectKeyFormat
			if aSimple {
				a = &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}}
			} else if aPartitioned {
				a = &TargetObjectKeyFormat{
					PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: aSource},
				}
			}
			if bSimple {
				b = &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}}
			} else if bPartitioned {
				b = &TargetObjectKeyFormat{
					PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: bSource},
				}
			}
			_ = bucketLogKeyFormatEqual(a, b)
		},
	)
}
