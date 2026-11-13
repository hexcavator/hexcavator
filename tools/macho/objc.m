// Objective-C metadata for Hexcavator's Mach-O tests (built by build.cmd):
// a root class of our own (no Foundation), a subclass with instance
// variables, properties, and class methods, a protocol with required and
// optional methods, and a category. Nothing here runs.

__attribute__((objc_root_class))
@interface Root {
    Class isa;
}
+ (id)alloc;
- (id)init;
@end

@implementation Root
+ (id)alloc {
    return 0;
}
- (id)init {
    return self;
}
@end

@protocol Drawable
- (void)drawAt:(int)x y:(int)y;
@optional
- (int)layer;
+ (const char *)kind;
@property(readonly) int size;
@end

@interface Shape : Root <Drawable> {
    int _sides;
    double _scale;
    char *_label;
}
@property(nonatomic) int sides;
@property(nonatomic, readonly) double scale;
+ (Shape *)unit;
@end

@implementation Shape
@synthesize sides = _sides;
@synthesize scale = _scale;
+ (Shape *)unit {
    return 0;
}
- (void)drawAt:(int)x y:(int)y {
    _sides = x + y;
}
- (int)size {
    return _sides;
}
@end

@interface Shape (Grow)
- (void)grow:(double)by;
@end

@implementation Shape (Grow)
- (void)grow:(double)by {
    _scale *= by;
}
@end
